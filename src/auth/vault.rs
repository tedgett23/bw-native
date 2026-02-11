use aes::Aes256;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, STANDARD_NO_PAD};
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use reqwest::blocking::Client;
use rsa::pkcs8::{DecodePrivateKey, Error as Pkcs8Error};
use rsa::{Oaep, RsaPrivateKey};
use serde_json::Value;
use sha1::Sha1;
use sha2::Sha256;
use std::collections::HashMap;

use super::errors::extract_error_message;

type Aes256CbcDecryptor = cbc::Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
struct SymmetricKey {
    enc: [u8; 32],
    mac: Option<[u8; 32]>,
}

struct CipherString {
    encryption_type: u32,
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
    mac: Option<Vec<u8>>,
    raw_iv: String,
    raw_ciphertext: String,
}

pub(super) struct DecryptedVaultView {
    pub(super) collections: Vec<String>,
    pub(super) items: Vec<String>,
}

impl SymmetricKey {
    fn from_slice(bytes: &[u8]) -> Result<Self, String> {
        match bytes.len() {
            32 => {
                let mut enc = [0_u8; 32];
                enc.copy_from_slice(bytes);
                Ok(Self { enc, mac: None })
            }
            64 => {
                let mut enc = [0_u8; 32];
                let mut mac = [0_u8; 32];
                enc.copy_from_slice(&bytes[..32]);
                mac.copy_from_slice(&bytes[32..64]);
                Ok(Self {
                    enc,
                    mac: Some(mac),
                })
            }
            length => Err(format!(
                "Unsupported key length ({length}). Expected 32 or 64 bytes."
            )),
        }
    }

    fn from_enc_mac(enc: [u8; 32], mac: [u8; 32]) -> Self {
        Self {
            enc,
            mac: Some(mac),
        }
    }
}

pub(super) fn sync_and_decrypt_vault(
    client: &Client,
    api_base_url: &str,
    access_token: &str,
    master_key: &[u8; 32],
    protected_user_key: &str,
) -> Result<DecryptedVaultView, String> {
    let sync_url = format!("{api_base_url}/sync?excludeDomains=true");
    let sync_response = client
        .get(sync_url)
        .bearer_auth(access_token)
        .send()
        .map_err(|error| format!("Sync request failed: {error}"))?;

    let status = sync_response.status();
    let body = sync_response.text().unwrap_or_default();

    if !status.is_success() {
        return Err(format!(
            "Sync failed ({status}): {}",
            extract_error_message(&body)
        ));
    }

    let mut sync_json: Value = serde_json::from_str(&body)
        .map_err(|error| format!("Invalid sync response JSON: {error}"))?;

    let user_key = decrypt_user_key(master_key, protected_user_key)?;
    decrypt_sync_payload(&mut sync_json, &user_key)?;
    Ok(build_vault_view(&sync_json))
}

fn decrypt_sync_payload(sync_json: &mut Value, user_key: &SymmetricKey) -> Result<(), String> {
    let user_private_key = decrypt_user_private_key(sync_json, user_key);
    let org_keys = decrypt_organization_keys(sync_json, user_key, user_private_key.as_ref());
    decrypt_collections(sync_json, &org_keys, user_key);
    decrypt_folders(sync_json, user_key);
    decrypt_ciphers(sync_json, &org_keys, user_key);
    Ok(())
}

fn decrypt_user_private_key(sync_json: &Value, user_key: &SymmetricKey) -> Option<RsaPrivateKey> {
    let encrypted_private_key = sync_json
        .get("profile")
        .and_then(|profile| profile.get("privateKey"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.to_string());

    let encrypted_private_key = match encrypted_private_key {
        Some(value) => value,
        None => return None,
    };

    let decrypted_bytes = match decrypt_cipher_string(&encrypted_private_key, user_key) {
        Ok(bytes) => bytes,
        Err(error) => {
            println!("Failed to decrypt profile private key: {error}");
            return None;
        }
    };

    match parse_rsa_private_key(&decrypted_bytes) {
        Ok(key) => Some(key),
        Err(error) => {
            println!("Failed to parse profile private key: {error}");
            None
        }
    }
}

fn decrypt_organization_keys(
    sync_json: &mut Value,
    user_key: &SymmetricKey,
    user_private_key: Option<&RsaPrivateKey>,
) -> HashMap<String, SymmetricKey> {
    let mut org_keys = HashMap::new();

    let Some(organizations) = sync_json
        .get_mut("profile")
        .and_then(|profile| profile.get_mut("organizations"))
        .and_then(Value::as_array_mut)
    else {
        return org_keys;
    };

    for organization in organizations.iter_mut() {
        let Some(organization_id) = organization
            .get("id")
            .and_then(Value::as_str)
            .map(|value| value.to_string())
        else {
            continue;
        };

        let encrypted_org_key = organization
            .get("key")
            .and_then(Value::as_str)
            .map(|value| value.to_string());

        let Some(encrypted_org_key) = encrypted_org_key else {
            continue;
        };

        let decrypted_org_key =
            decrypt_key_material(&encrypted_org_key, user_key, user_private_key)
                .and_then(|bytes| SymmetricKey::from_slice(&bytes));

        match decrypted_org_key {
            Ok(org_key) => {
                org_keys.insert(organization_id, org_key);
            }
            Err(error) => {
                println!("Failed to decrypt organization key: {error}");
            }
        }
    }

    org_keys
}

fn decrypt_collections(
    sync_json: &mut Value,
    org_keys: &HashMap<String, SymmetricKey>,
    user_key: &SymmetricKey,
) {
    let Some(collections) = sync_json
        .get_mut("collections")
        .and_then(Value::as_array_mut)
    else {
        return;
    };

    for collection in collections.iter_mut() {
        let base_key = resolve_entity_key(collection, org_keys, user_key);
        decrypt_string_field(collection, "name", &base_key);
    }
}

fn decrypt_folders(sync_json: &mut Value, user_key: &SymmetricKey) {
    let Some(folders) = sync_json.get_mut("folders").and_then(Value::as_array_mut) else {
        return;
    };

    for folder in folders.iter_mut() {
        decrypt_string_field(folder, "name", user_key);
    }
}

fn decrypt_ciphers(
    sync_json: &mut Value,
    org_keys: &HashMap<String, SymmetricKey>,
    user_key: &SymmetricKey,
) {
    let Some(ciphers) = sync_json.get_mut("ciphers").and_then(Value::as_array_mut) else {
        return;
    };

    for cipher in ciphers.iter_mut() {
        let base_key = resolve_entity_key(cipher, org_keys, user_key);
        let content_key = resolve_cipher_content_key(cipher, &base_key).unwrap_or(base_key);

        decrypt_string_field(cipher, "name", &content_key);
        decrypt_string_field(cipher, "notes", &content_key);

        if let Some(login) = cipher.get_mut("login") {
            decrypt_string_field(login, "username", &content_key);
            decrypt_string_field(login, "password", &content_key);
            decrypt_string_field(login, "totp", &content_key);
            decrypt_uris(login, &content_key);
        }

        if let Some(identity) = cipher.get_mut("identity") {
            decrypt_json_value(identity, &content_key);
        }

        if let Some(card) = cipher.get_mut("card") {
            decrypt_json_value(card, &content_key);
        }

        if let Some(secure_note) = cipher.get_mut("secureNote") {
            decrypt_json_value(secure_note, &content_key);
        }

        if let Some(ssh_key) = cipher.get_mut("sshKey") {
            decrypt_json_value(ssh_key, &content_key);
        }

        if let Some(fields) = cipher.get_mut("fields") {
            decrypt_json_value(fields, &content_key);
        }

        if let Some(attachments) = cipher.get_mut("attachments") {
            decrypt_json_value(attachments, &content_key);
        }

        decrypt_cipher_data(cipher, &content_key);
    }
}

fn resolve_entity_key(
    entity: &Value,
    org_keys: &HashMap<String, SymmetricKey>,
    user_key: &SymmetricKey,
) -> SymmetricKey {
    let organization_id = entity.get("organizationId").and_then(Value::as_str);
    if let Some(organization_id) = organization_id {
        if let Some(org_key) = org_keys.get(organization_id) {
            return org_key.clone();
        }
    }

    user_key.clone()
}

fn resolve_cipher_content_key(
    cipher: &Value,
    base_key: &SymmetricKey,
) -> Result<SymmetricKey, String> {
    let encrypted_item_key = cipher
        .get("key")
        .and_then(Value::as_str)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty());

    let Some(encrypted_item_key) = encrypted_item_key else {
        return Ok(base_key.clone());
    };

    let raw_item_key = decrypt_key_material(encrypted_item_key, base_key, None)?;
    SymmetricKey::from_slice(&raw_item_key)
}

fn decrypt_key_material(
    ciphertext: &str,
    symmetric_key: &SymmetricKey,
    private_key: Option<&RsaPrivateKey>,
) -> Result<Vec<u8>, String> {
    match parse_encryption_type(ciphertext)? {
        0 | 2 => decrypt_cipher_string(ciphertext, symmetric_key),
        3 | 4 | 5 | 6 => {
            let private_key = private_key
                .ok_or_else(|| "Asymmetric ciphertext requires a private key.".to_string())?;
            decrypt_asymmetric_cipher_string(ciphertext, private_key)
        }
        other => Err(format!("Unsupported encryption type: {other}")),
    }
}

fn parse_encryption_type(ciphertext: &str) -> Result<u32, String> {
    let (prefix, _) = ciphertext
        .split_once('.')
        .ok_or_else(|| "Ciphertext is missing encryption type prefix.".to_string())?;
    prefix
        .parse()
        .map_err(|_| "Ciphertext has invalid encryption type prefix.".to_string())
}

fn decrypt_asymmetric_cipher_string(
    ciphertext: &str,
    private_key: &RsaPrivateKey,
) -> Result<Vec<u8>, String> {
    let (prefix, payload) = ciphertext
        .split_once('.')
        .ok_or_else(|| "Ciphertext is missing encryption type prefix.".to_string())?;

    let encryption_type: u32 = prefix
        .parse()
        .map_err(|_| "Ciphertext has invalid encryption type prefix.".to_string())?;

    let parts: Vec<&str> = payload.split('|').collect();
    let encrypted_data = match encryption_type {
        3 | 4 => {
            if parts.len() != 1 {
                return Err("RSA ciphertext type must contain one segment.".to_string());
            }
            decode_base64(parts[0])?
        }
        5 | 6 => {
            if parts.len() < 1 {
                return Err("Legacy RSA ciphertext is missing data segment.".to_string());
            }
            decode_base64(parts[0])?
        }
        other => return Err(format!("Unsupported asymmetric encryption type: {other}")),
    };

    match encryption_type {
        3 | 5 => private_key
            .decrypt(Oaep::new::<Sha256>(), &encrypted_data)
            .map_err(|_| "RSA-OAEP-SHA256 decrypt failed.".to_string()),
        4 | 6 => private_key
            .decrypt(Oaep::new::<Sha1>(), &encrypted_data)
            .map_err(|_| "RSA-OAEP-SHA1 decrypt failed.".to_string()),
        _ => Err("Unsupported asymmetric encryption type.".to_string()),
    }
}

fn parse_rsa_private_key(bytes: &[u8]) -> Result<RsaPrivateKey, String> {
    RsaPrivateKey::from_pkcs8_der(bytes)
        .or_else(|_| parse_rsa_private_key_from_utf8(bytes))
        .map_err(|error| format!("Invalid PKCS8 private key: {error}"))
}

fn parse_rsa_private_key_from_utf8(bytes: &[u8]) -> Result<RsaPrivateKey, Pkcs8Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Pkcs8Error::KeyMalformed)?;
    RsaPrivateKey::from_pkcs8_pem(text)
}

fn decrypt_uris(login: &mut Value, key: &SymmetricKey) {
    let Some(uris) = login.get_mut("uris").and_then(Value::as_array_mut) else {
        return;
    };

    for uri in uris.iter_mut() {
        decrypt_string_field(uri, "uri", key);
    }
}

fn decrypt_cipher_data(cipher: &mut Value, key: &SymmetricKey) {
    let data_string = cipher
        .get("data")
        .and_then(Value::as_str)
        .map(|value| value.to_string());

    let Some(data_string) = data_string else {
        return;
    };

    let Ok(mut data_json) = serde_json::from_str::<Value>(&data_string) else {
        return;
    };

    decrypt_json_value(&mut data_json, key);

    if let Some(data_slot) = cipher.get_mut("data") {
        *data_slot = data_json;
    }
}

fn decrypt_string_field(value: &mut Value, field_name: &str, key: &SymmetricKey) {
    let Some(field) = value.get_mut(field_name) else {
        return;
    };

    let Value::String(text) = field else {
        return;
    };

    let candidate = text.clone();
    if let Ok(plaintext) = decrypt_ciphertext_string(&candidate, key) {
        *text = plaintext;
    }
}

fn decrypt_user_key(
    master_key: &[u8; 32],
    protected_user_key: &str,
) -> Result<SymmetricKey, String> {
    if let Ok((enc_type, payload)) = protected_user_key
        .split_once('.')
        .ok_or_else(|| "missing cipher type".to_string())
    {
        let parts: Vec<&str> = payload.split('|').collect();
        let segment_lengths: Vec<usize> = parts.iter().map(|part| part.len()).collect();
        println!(
            "Protected user key metadata: enc_type={enc_type} segments={} segment_lengths={:?}",
            parts.len(),
            segment_lengths
        );
    } else {
        println!(
            "Protected user key metadata: unparsable cipher string, raw_len={}",
            protected_user_key.len()
        );
    }

    let mut candidates = vec![SymmetricKey::from_slice(master_key)?];

    if let Ok((enc, mac)) = hkdf_expand_master_key(master_key) {
        candidates.push(SymmetricKey::from_enc_mac(enc, mac));
        candidates.push(SymmetricKey::from_enc_mac(mac, enc));
    }

    let mut last_error = "No key candidates were attempted.".to_string();

    for (index, candidate) in candidates.into_iter().enumerate() {
        match decrypt_cipher_string(protected_user_key, &candidate) {
            Ok(raw_user_key) => return SymmetricKey::from_slice(&raw_user_key),
            Err(error) => {
                println!(
                    "Protected user key decrypt attempt {} failed: {}",
                    index + 1,
                    error
                );
                last_error = error;
            }
        }
    }

    Err(format!(
        "Failed to decrypt user key from token response: {last_error}"
    ))
}

fn hkdf_expand_master_key(master_key: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), String> {
    let enc_bytes = hkdf_expand_sha256(master_key, b"enc", 32)?;
    let mac_bytes = hkdf_expand_sha256(master_key, b"mac", 32)?;

    let mut enc = [0_u8; 32];
    let mut mac = [0_u8; 32];
    enc.copy_from_slice(&enc_bytes);
    mac.copy_from_slice(&mac_bytes);

    Ok((enc, mac))
}

fn hkdf_expand_sha256(ikm: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, String> {
    // Match Bitwarden's stretch_key implementation: HKDF-Expand using the 32-byte master key
    // directly as PRK (no extract phase), with info="enc"/"mac".
    let mut okm = Vec::with_capacity(len);
    let mut t = Vec::new();
    let mut counter = 1_u8;

    while okm.len() < len {
        let mut expand = HmacSha256::new_from_slice(ikm)
            .map_err(|error| format!("HKDF expand failed: {error}"))?;
        expand.update(&t);
        expand.update(info);
        expand.update(&[counter]);

        t = expand.finalize().into_bytes().to_vec();
        okm.extend_from_slice(&t);
        counter = counter.saturating_add(1);
    }

    okm.truncate(len);
    Ok(okm)
}

fn decrypt_json_value(value: &mut Value, key: &SymmetricKey) {
    match value {
        Value::Object(map) => {
            for entry in map.values_mut() {
                decrypt_json_value(entry, key);
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                decrypt_json_value(item, key);
            }
        }
        Value::String(text) => {
            let candidate = text.clone();
            if let Ok(plaintext) = decrypt_ciphertext_string(&candidate, key) {
                *text = plaintext;
            }
        }
        _ => {}
    }
}

fn decrypt_ciphertext_string(ciphertext: &str, key: &SymmetricKey) -> Result<String, String> {
    let plaintext = decrypt_cipher_string(ciphertext, key)?;
    match String::from_utf8(plaintext) {
        Ok(text) => Ok(text),
        Err(utf8_error) => {
            let bytes = utf8_error.into_bytes();
            Ok(format!(
                "<binary {} bytes: {}>",
                bytes.len(),
                BASE64_STANDARD.encode(bytes)
            ))
        }
    }
}

fn decrypt_cipher_string(ciphertext: &str, key: &SymmetricKey) -> Result<Vec<u8>, String> {
    let parsed = parse_cipher_string(ciphertext)?;

    if parsed.encryption_type == 2 {
        let provided_mac = parsed
            .mac
            .as_ref()
            .ok_or_else(|| "Ciphertext missing MAC field.".to_string())?;
        let mac_key = key.mac.as_ref().ok_or_else(|| {
            "Ciphertext requires MAC key but key does not include one.".to_string()
        })?;

        verify_mac(&parsed, mac_key, provided_mac)?;
    }

    let mut buffer = parsed.ciphertext.clone();
    let decryptor = Aes256CbcDecryptor::new_from_slices(&key.enc, &parsed.iv)
        .map_err(|error| format!("Failed to initialize AES-CBC decryptor: {error}"))?;
    let plaintext = decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| "AES-CBC decryption failed (invalid padding or key).".to_string())?;

    Ok(plaintext.to_vec())
}

fn parse_cipher_string(input: &str) -> Result<CipherString, String> {
    let (encryption_type, payload) = input
        .split_once('.')
        .ok_or_else(|| "Ciphertext is missing encryption type prefix.".to_string())?;

    let encryption_type: u32 = encryption_type
        .parse()
        .map_err(|_| "Ciphertext has invalid encryption type prefix.".to_string())?;

    let parts: Vec<&str> = payload.split('|').collect();

    match encryption_type {
        0 => {
            if parts.len() != 2 {
                return Err("Type 0 ciphertext must contain iv|ciphertext.".to_string());
            }
            Ok(CipherString {
                encryption_type,
                iv: decode_base64(parts[0])?,
                ciphertext: decode_base64(parts[1])?,
                mac: None,
                raw_iv: parts[0].to_string(),
                raw_ciphertext: parts[1].to_string(),
            })
        }
        2 => {
            if parts.len() != 3 {
                return Err("Type 2 ciphertext must contain iv|ciphertext|mac.".to_string());
            }
            Ok(CipherString {
                encryption_type,
                iv: decode_base64(parts[0])?,
                ciphertext: decode_base64(parts[1])?,
                mac: Some(decode_base64(parts[2])?),
                raw_iv: parts[0].to_string(),
                raw_ciphertext: parts[1].to_string(),
            })
        }
        other => Err(format!("Unsupported encryption type: {other}")),
    }
}

fn verify_mac(
    parsed: &CipherString,
    mac_key: &[u8; 32],
    provided_mac: &[u8],
) -> Result<(), String> {
    let mut variant_a = HmacSha256::new_from_slice(mac_key)
        .map_err(|error| format!("Invalid MAC key size: {error}"))?;
    variant_a.update(&parsed.iv);
    variant_a.update(&parsed.ciphertext);
    if variant_a.verify_slice(provided_mac).is_ok() {
        return Ok(());
    }

    let mut variant_b = HmacSha256::new_from_slice(mac_key)
        .map_err(|error| format!("Invalid MAC key size: {error}"))?;
    variant_b.update(&parsed.ciphertext);
    if variant_b.verify_slice(provided_mac).is_ok() {
        return Ok(());
    }

    let mut variant_c = HmacSha256::new_from_slice(mac_key)
        .map_err(|error| format!("Invalid MAC key size: {error}"))?;
    let combined = format!("{}|{}", parsed.raw_iv, parsed.raw_ciphertext);
    variant_c.update(combined.as_bytes());
    if variant_c.verify_slice(provided_mac).is_ok() {
        return Ok(());
    }

    Err("Ciphertext MAC verification failed.".to_string())
}

fn decode_base64(data: &str) -> Result<Vec<u8>, String> {
    BASE64_STANDARD
        .decode(data)
        .or_else(|_| STANDARD_NO_PAD.decode(data))
        .map_err(|error| format!("Invalid base64 ciphertext segment: {error}"))
}

fn build_vault_view(sync_json: &Value) -> DecryptedVaultView {
    DecryptedVaultView {
        collections: build_collection_list(sync_json),
        items: build_item_list(sync_json),
    }
}

fn build_collection_list(sync_json: &Value) -> Vec<String> {
    let Some(collections) = sync_json.get("collections").and_then(Value::as_array) else {
        return Vec::new();
    };

    collections
        .iter()
        .filter_map(|collection| {
            let name = collection
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("Unnamed collection");
            Some(name.to_string())
        })
        .collect()
}

fn build_item_list(sync_json: &Value) -> Vec<String> {
    let Some(ciphers) = sync_json.get("ciphers").and_then(Value::as_array) else {
        return Vec::new();
    };

    ciphers
        .iter()
        .map(|cipher| {
            let name = cipher
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("Unnamed item");

            let username = cipher
                .get("login")
                .and_then(|login| login.get("username"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty());

            match username {
                Some(username) => format!("{name} ({username})"),
                None => name.to_string(),
            }
        })
        .collect()
}
