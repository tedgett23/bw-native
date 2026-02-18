//! Trusted Device Encryption (TDE) helpers.
//!
//! Responsibilities:
//! - Generate and persist a 32-byte AES-256 device key to
//!   `~/.config/bw-native/device_key.json`
//! - Encrypt / decrypt data (CipherString type-2, AES-CBC + HMAC-SHA256) with
//!   the device key so the server-returned `encryptedPrivateKey` and
//!   `encryptedUserKey` can be unwrapped locally.
//! - Generate an ephemeral RSA-2048 keypair for auth-request flows.
//! - Decrypt the user key from an RSA-OAEP encrypted blob returned by an
//!   approving device or admin.
//! - Encrypt the user key and private key with the device key, and the public
//!   key with the user key, ready for `PUT /devices/identifier/{id}/trust`.

use aes::Aes256;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::Hmac;
use rsa::pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::rand_core::OsRng;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::PathBuf;

type Aes256CbcEncryptor = cbc::Encryptor<Aes256>;
type Aes256CbcDecryptor = cbc::Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

// ── Device key storage ──────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct DeviceKeyFile {
    /// Server/identity URL this key is scoped to (so different servers get
    /// different device keys).
    server_url: String,
    /// The device identifier UUID sent on every token request.
    device_identifier: String,
    /// 32-byte AES-256 device key, Base64-encoded.
    device_key_b64: String,
}

fn config_dir() -> Option<PathBuf> {
    dirs_from_env().or_else(|| {
        // Fallback: ~/.config/bw-native
        home_dir().map(|h| h.join(".config").join("bw-native"))
    })
}

fn dirs_from_env() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .map(|p| p.join("bw-native"))
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn key_file_path() -> Result<PathBuf, String> {
    let dir = config_dir().ok_or_else(|| "Cannot determine config directory".to_string())?;
    Ok(dir.join("device_key.json"))
}

/// Load the stored device key for the given server URL, if it exists.
pub(super) fn load_device_key(server_url: &str) -> Option<StoredDeviceKey> {
    let path = key_file_path().ok()?;
    let mut file = std::fs::File::open(&path).ok()?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).ok()?;

    let records: Vec<DeviceKeyFile> = serde_json::from_str(&contents).ok()?;
    let record = records.into_iter().find(|r| r.server_url == server_url)?;

    let key_bytes = BASE64.decode(&record.device_key_b64).ok()?;
    if key_bytes.len() != 32 {
        return None;
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Some(StoredDeviceKey {
        device_identifier: record.device_identifier,
        key,
    })
}

/// Save (or overwrite) the device key for the given server URL.
pub(super) fn save_device_key(server_url: &str, stored: &StoredDeviceKey) -> Result<(), String> {
    let path = key_file_path()?;

    // Create directory if necessary
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("Cannot create config directory: {e}"))?;
    }

    // Read existing records, filtering out any old record for this server
    let mut records: Vec<DeviceKeyFile> = if path.exists() {
        let mut file =
            std::fs::File::open(&path).map_err(|e| format!("Cannot read device key file: {e}"))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| format!("Cannot read device key file: {e}"))?;
        serde_json::from_str(&contents).unwrap_or_default()
    } else {
        Vec::new()
    };

    records.retain(|r| r.server_url != server_url);
    records.push(DeviceKeyFile {
        server_url: server_url.to_string(),
        device_identifier: stored.device_identifier.clone(),
        device_key_b64: BASE64.encode(stored.key),
    });

    let json = serde_json::to_string_pretty(&records)
        .map_err(|e| format!("Cannot serialize device key: {e}"))?;

    // Write atomically via a temp file in the same directory
    let tmp_path = path.with_extension("json.tmp");
    let mut tmp = std::fs::File::create(&tmp_path)
        .map_err(|e| format!("Cannot write device key file: {e}"))?;
    tmp.write_all(json.as_bytes())
        .map_err(|e| format!("Cannot write device key file: {e}"))?;
    tmp.flush()
        .map_err(|e| format!("Cannot flush device key file: {e}"))?;
    std::fs::rename(&tmp_path, &path).map_err(|e| format!("Cannot save device key file: {e}"))?;

    Ok(())
}

/// A loaded or freshly-generated device key.
pub(super) struct StoredDeviceKey {
    pub(super) device_identifier: String,
    pub(super) key: [u8; 32],
}

/// Generate a brand-new random device key and device identifier.
pub(super) fn generate_device_key() -> StoredDeviceKey {
    let mut key = [0u8; 32];
    // Use the OS CSPRNG via the `rsa` crate's re-exported rand_core
    use rsa::rand_core::RngCore;
    OsRng.fill_bytes(&mut key);

    StoredDeviceKey {
        device_identifier: uuid::Uuid::new_v4().to_string(),
        key,
    }
}

// ── CipherString helpers ─────────────────────────────────────────────────────

/// Encrypt `plaintext` with the device key (type-2: AES-256-CBC + HMAC-SHA256).
/// Returns a CipherString in the format: `2.<iv_b64>|<ct_b64>|<mac_b64>`
pub(super) fn encrypt_with_device_key(
    device_key: &[u8; 32],
    plaintext: &[u8],
) -> Result<String, String> {
    // Derive separate enc + mac keys via HKDF-SHA256
    let (enc_key, mac_key) = hkdf_expand(device_key);
    aes_cbc_encrypt_hmac(&enc_key, &mac_key, plaintext)
}

/// Decrypt a type-2 CipherString using the device key.
pub(super) fn decrypt_with_device_key(
    device_key: &[u8; 32],
    cipher_string: &str,
) -> Result<Vec<u8>, String> {
    let (enc_key, mac_key) = hkdf_expand(device_key);
    aes_cbc_decrypt_hmac(&enc_key, &mac_key, cipher_string)
}

/// Decrypt a type-2 CipherString using a raw 64-byte enc+mac key (user key).
#[allow(dead_code)]
pub(super) fn decrypt_with_user_key_bytes(
    user_key_bytes: &[u8; 64],
    cipher_string: &str,
) -> Result<Vec<u8>, String> {
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    enc.copy_from_slice(&user_key_bytes[..32]);
    mac.copy_from_slice(&user_key_bytes[32..]);
    aes_cbc_decrypt_hmac(&enc, &mac, cipher_string)
}

/// Encrypt `plaintext` with a raw 64-byte enc+mac key (user key).
pub(super) fn encrypt_with_user_key_bytes(
    user_key_bytes: &[u8; 64],
    plaintext: &[u8],
) -> Result<String, String> {
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    enc.copy_from_slice(&user_key_bytes[..32]);
    mac.copy_from_slice(&user_key_bytes[32..]);
    aes_cbc_encrypt_hmac(&enc, &mac, plaintext)
}

// ── RSA ephemeral keypair ────────────────────────────────────────────────────

pub(super) struct EphemeralKeypair {
    pub(super) private_key: RsaPrivateKey,
    pub(super) public_key_b64: String,
}

/// Generate a 2048-bit RSA keypair for an auth request.
/// The public key is returned as a Base64-encoded DER SubjectPublicKeyInfo blob
/// (same format the official Bitwarden client uses).
pub(super) fn generate_ephemeral_keypair() -> Result<EphemeralKeypair, String> {
    let private_key = RsaPrivateKey::new(&mut OsRng, 2048)
        .map_err(|e| format!("Failed to generate RSA keypair: {e}"))?;
    let public_key = RsaPublicKey::from(&private_key);
    let der = public_key
        .to_public_key_der()
        .map_err(|e| format!("Failed to encode RSA public key: {e}"))?;
    let public_key_b64 = BASE64.encode(der.as_bytes());
    Ok(EphemeralKeypair {
        private_key,
        public_key_b64,
    })
}

/// Decode a Base64 DER public key and return an `RsaPublicKey`.
#[allow(dead_code)]
pub(super) fn decode_rsa_public_key_b64(b64: &str) -> Result<RsaPublicKey, String> {
    let der = BASE64
        .decode(b64)
        .map_err(|e| format!("Invalid Base64 in public key: {e}"))?;
    RsaPublicKey::from_public_key_der(&der).map_err(|e| format!("Invalid DER public key: {e}"))
}

/// Decrypt a user key that was RSA-OAEP-SHA1 encrypted for our ephemeral
/// keypair (the format Bitwarden uses in auth-request responses).
/// The cipher string may be prefixed with `4.` (RSA-OAEP SHA-1) or bare Base64.
pub(super) fn rsa_decrypt_user_key(
    private_key: &RsaPrivateKey,
    encrypted_b64: &str,
) -> Result<Vec<u8>, String> {
    // Strip type prefix if present (e.g. "4.<base64>")
    let b64 = if encrypted_b64.contains('.') {
        encrypted_b64
            .split_once('.')
            .map(|(_, rest)| rest)
            .unwrap_or(encrypted_b64)
    } else {
        encrypted_b64
    };

    let ciphertext = BASE64
        .decode(b64)
        .map_err(|e| format!("Invalid Base64 in encrypted user key: {e}"))?;

    let padding = Oaep::new::<sha1::Sha1>();
    private_key
        .decrypt(padding, &ciphertext)
        .map_err(|e| format!("RSA-OAEP decryption of user key failed: {e}"))
}

/// Encrypt `plaintext` with an RSA public key using OAEP-SHA1.
/// Returns Base64 (no type prefix) — callers prepend the type prefix as needed.
pub(super) fn rsa_encrypt(public_key: &RsaPublicKey, plaintext: &[u8]) -> Result<String, String> {
    let padding = Oaep::new::<sha1::Sha1>();
    let encrypted = public_key
        .encrypt(&mut OsRng, padding, plaintext)
        .map_err(|e| format!("RSA-OAEP encryption failed: {e}"))?;
    Ok(BASE64.encode(encrypted))
}

/// Encode an RSA private key as PKCS#8 DER bytes.
pub(super) fn private_key_to_der(key: &RsaPrivateKey) -> Result<Vec<u8>, String> {
    Ok(key
        .to_pkcs8_der()
        .map_err(|e| format!("Failed to encode private key: {e}"))?
        .as_bytes()
        .to_vec())
}

// ── Fingerprint ──────────────────────────────────────────────────────────────

/// Derive a human-readable fingerprint phrase from a user email and a public
/// key, matching the algorithm the official Bitwarden client uses.
/// Format: five lowercase English words joined by hyphens.
pub(super) fn fingerprint_phrase(email: &str, public_key_b64: &str) -> String {
    let public_key_bytes = BASE64.decode(public_key_b64).unwrap_or_default();
    // HKDF: salt = SHA-256(email), ikm = public_key_bytes, info = email bytes
    let salt = Sha256::digest(email.as_bytes());
    let fingerprint = hkdf_extract_expand(&salt, &public_key_bytes, email.as_bytes(), 32);
    encode_fingerprint(&fingerprint)
}

const FINGERPRINT_WORDLIST: &[&str] = &[
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd",
    "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire",
    "across", "act", "action", "actor", "actress", "actual", "adapt", "add", "addict", "address",
    "adjust", "admit", "adult", "advance", "advice", "aerobic", "afford", "afraid", "again",
    "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol",
    "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also",
    "alter", "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor",
    "ancient", "anger", "angle", "angry", "animal", "ankle", "announce", "annual", "another",
    "answer", "antenna", "antique", "anxiety", "any", "apart", "apology", "appear", "apple",
    "approve", "april", "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
    "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist",
    "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma", "athlete",
    "atom", "attack", "attend", "attitude", "attract", "auction", "audit", "august", "aunt",
    "author", "auto", "autumn", "average", "avocado", "avoid", "awake", "aware", "away", "awesome",
    "awful", "awkward", "axis",
];

fn encode_fingerprint(bytes: &[u8]) -> String {
    let words: Vec<&str> = bytes
        .chunks(2)
        .take(5)
        .map(|chunk| {
            let idx = if chunk.len() == 2 {
                (((chunk[0] as usize) << 8) | chunk[1] as usize) % FINGERPRINT_WORDLIST.len()
            } else {
                chunk[0] as usize % FINGERPRINT_WORDLIST.len()
            };
            FINGERPRINT_WORDLIST[idx]
        })
        .collect();
    words.join("-")
}

// ── HKDF / AES internals ─────────────────────────────────────────────────────

/// HKDF-Extract then HKDF-Expand to derive `length` bytes.
/// Uses SHA-256 for both steps.
fn hkdf_extract_expand(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    use hmac::Mac as _;
    // Extract
    let mut extract_mac = HmacSha256::new_from_slice(salt).expect("HMAC accepts any key size");
    extract_mac.update(ikm);
    let prk = extract_mac.finalize().into_bytes();

    // Expand
    let mut output = Vec::with_capacity(length);
    let mut t = Vec::new();
    let mut counter: u8 = 1;
    while output.len() < length {
        let mut expand_mac = HmacSha256::new_from_slice(&prk).expect("HMAC accepts any key size");
        expand_mac.update(&t);
        expand_mac.update(info);
        expand_mac.update(&[counter]);
        t = expand_mac.finalize().into_bytes().to_vec();
        output.extend_from_slice(&t);
        counter += 1;
    }
    output.truncate(length);
    output
}

/// Derive a 64-byte enc+mac key from a 32-byte device key using HKDF-SHA256.
/// Matches the Bitwarden SDK behaviour for device-key-based encryption.
fn hkdf_expand(device_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // For device key expansion: salt = device_key, ikm = device_key, info = b""
    // We derive 64 bytes and split into enc (first 32) + mac (last 32).
    // This mirrors how the SDK stretches a 32-byte symmetric key.
    use hmac::Mac as _;

    // HKDF-Extract: PRK = HMAC-SHA256(salt=device_key, ikm=device_key)
    let mut mac = HmacSha256::new_from_slice(device_key).expect("HMAC accepts any key size");
    mac.update(device_key);
    let prk = mac.finalize().into_bytes();

    // HKDF-Expand T(1) for enc key
    let mut mac1 = HmacSha256::new_from_slice(&prk).expect("HMAC accepts any key size");
    mac1.update(b"\x01");
    let t1 = mac1.finalize().into_bytes();

    // HKDF-Expand T(2) for mac key
    let mut mac2 = HmacSha256::new_from_slice(&prk).expect("HMAC accepts any key size");
    mac2.update(&t1);
    mac2.update(b"\x02");
    let t2 = mac2.finalize().into_bytes();

    let mut enc = [0u8; 32];
    let mut mac_key = [0u8; 32];
    enc.copy_from_slice(&t1);
    mac_key.copy_from_slice(&t2);
    (enc, mac_key)
}

fn random_iv() -> [u8; 16] {
    use rsa::rand_core::RngCore;
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);
    iv
}

fn aes_cbc_encrypt_hmac(
    enc_key: &[u8; 32],
    mac_key: &[u8; 32],
    plaintext: &[u8],
) -> Result<String, String> {
    let iv = random_iv();
    let encryptor = Aes256CbcEncryptor::new(enc_key.into(), iv.as_ref().into());
    let msg_len = plaintext.len();
    let mut buf = plaintext.to_vec();
    buf.resize(msg_len + 16, 0);
    let ciphertext = encryptor
        .encrypt_padded_mut::<Pkcs7>(&mut buf, msg_len)
        .map_err(|e| format!("AES-CBC encryption failed: {e}"))?
        .to_vec();

    // MAC = HMAC-SHA256(mac_key, iv || ciphertext)
    use hmac::Mac as _;
    let mut mac =
        HmacSha256::new_from_slice(mac_key).map_err(|e| format!("HMAC key error: {e}"))?;
    mac.update(&iv);
    mac.update(&ciphertext);
    let mac_bytes = mac.finalize().into_bytes();

    Ok(format!(
        "2.{}|{}|{}",
        BASE64.encode(iv),
        BASE64.encode(&ciphertext),
        BASE64.encode(mac_bytes)
    ))
}

fn aes_cbc_decrypt_hmac(
    enc_key: &[u8; 32],
    mac_key: &[u8; 32],
    cipher_string: &str,
) -> Result<Vec<u8>, String> {
    // Strip optional type prefix
    let body = if let Some(rest) = cipher_string.strip_prefix("2.") {
        rest
    } else {
        cipher_string
    };

    let parts: Vec<&str> = body.splitn(3, '|').collect();
    if parts.len() < 2 {
        return Err("Invalid CipherString format".to_string());
    }

    let iv = BASE64
        .decode(parts[0])
        .map_err(|e| format!("Invalid IV: {e}"))?;
    let mut ciphertext = BASE64
        .decode(parts[1])
        .map_err(|e| format!("Invalid ciphertext: {e}"))?;

    // Verify MAC if present
    if parts.len() == 3 && !parts[2].is_empty() {
        let expected_mac = BASE64
            .decode(parts[2])
            .map_err(|e| format!("Invalid MAC: {e}"))?;
        use hmac::Mac as _;
        let mut mac =
            HmacSha256::new_from_slice(mac_key).map_err(|e| format!("HMAC key error: {e}"))?;
        mac.update(&iv);
        mac.update(&ciphertext);
        mac.verify_slice(&expected_mac)
            .map_err(|_| "MAC verification failed for device-key-encrypted data".to_string())?;
    }

    let iv_arr: [u8; 16] = iv
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid IV length".to_string())?;
    let decryptor = Aes256CbcDecryptor::new(enc_key.into(), iv_arr.as_ref().into());
    let plaintext = decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut ciphertext)
        .map_err(|e| format!("AES-CBC decryption failed: {e}"))?;
    Ok(plaintext.to_vec())
}

// ── Access code ──────────────────────────────────────────────────────────────

/// Generate a 25-character alphanumeric access code for auth requests.
pub(super) fn generate_access_code() -> String {
    use rsa::rand_core::RngCore;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut out = String::with_capacity(25);
    let mut buf = [0u8; 1];
    while out.len() < 25 {
        OsRng.fill_bytes(&mut buf);
        let idx = buf[0] as usize;
        if idx < (256 / CHARSET.len()) * CHARSET.len() {
            out.push(CHARSET[idx % CHARSET.len()] as char);
        }
    }
    out
}
