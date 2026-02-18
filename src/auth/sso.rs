use std::io::{Read as IoRead, Write as IoWrite};
use std::net::TcpListener;
use std::sync::mpsc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE;
use reqwest::blocking::Client;
use serde_json::from_str;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::crypto::{derive_master_key, kdf_config_from_prelogin};
use super::device_trust::{
    StoredDeviceKey, decrypt_with_device_key, encrypt_with_device_key, encrypt_with_user_key_bytes,
    fingerprint_phrase, generate_access_code, generate_device_key, generate_ephemeral_keypair,
    load_device_key, private_key_to_der, rsa_decrypt_user_key, rsa_encrypt, save_device_key,
};
use super::errors::extract_error_message;
use super::models::{
    AuthRequestApprovalResponse, AuthRequestResponse, CreateAuthRequest, PreloginResponse,
    SsoPreValidateResponse, TokenSuccessResponse, TrustDeviceRequest,
};
use super::server::{
    normalize_email, resolve_api_base_url, resolve_identity_base_url, resolve_web_vault_url,
};
use super::vault::sync_and_decrypt_vault;
use super::workflow::{LoginResult, VaultItemFieldView, VaultItemView};

const SSO_PORT_START: u16 = 8065;
const SSO_PORT_END: u16 = 8070;
const SSO_CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);

/// Auth-request type 1 = device approval ("AuthenticateAndUnlock").
const AUTH_REQUEST_TYPE_DEVICE: u32 = 1;
/// Auth-request type 7 = admin-console approval.
const AUTH_REQUEST_TYPE_ADMIN: u32 = 7;

// ── Public result types ───────────────────────────────────────────────────────

/// Describes the result of the SSO token exchange.
pub enum SsoTokenResult {
    /// Token exchange succeeded and the user has a master password.
    NeedsMasterPassword {
        access_token: String,
        protected_user_key: String,
        api_base_url: String,
        kdf_config: KdfConfigSnapshot,
        client: Client,
    },
    /// TDE account; the device is already trusted — vault decrypted automatically.
    TrustedDeviceDecrypted(LoginResult),
    /// TDE account, device not yet trusted.
    /// Two parallel auth requests (device approval + admin approval) have been
    /// submitted. The UI should show the fingerprint and poll for approval.
    NeedsDeviceApproval {
        /// State needed to complete the flow once approved.
        pending: TdePendingState,
        /// Human-readable fingerprint to display to the approver.
        fingerprint: String,
    },
    /// Token exchange succeeded but no decryption path was found at all.
    NoDecryptionPath { message: String },
}

/// Everything needed to finish the TDE flow after an auth-request is approved.
/// `Client` is cheaply clone-able (it's an `Arc` internally).
#[derive(Clone)]
pub struct TdePendingState {
    pub access_token: String,
    pub api_base_url: String,
    pub identity_base_url: String,
    pub server_url: String,
    #[allow(dead_code)]
    pub email: String,
    #[allow(dead_code)]
    pub kdf_config: KdfConfigSnapshot,
    pub client: Client,
    /// Auth-request IDs to poll (device-approval and/or admin-approval).
    pub auth_request_ids: Vec<String>,
    /// The ephemeral RSA private key whose public key the approver used to
    /// encrypt the user key.
    pub ephemeral_private_key_der: Vec<u8>,
    /// Device identifier sent with the token request (needed for trust setup).
    pub device_identifier: String,
}

/// Snapshot of KDF config from the token response (SSO doesn't do prelogin).
#[derive(Clone)]
pub struct KdfConfigSnapshot {
    pub kdf: Option<u32>,
    pub iterations: Option<u32>,
    pub memory: Option<u32>,
    pub parallelism: Option<u32>,
}

/// Result from the browser callback — the authorization code.
struct SsoCallbackResult {
    code: String,
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Begin the SSO authentication flow and return what the caller needs to do
/// next.  See [`SsoTokenResult`] for the possible outcomes.
pub fn try_sso_login(
    server_url: &str,
    org_identifier: &str,
    email: &str,
) -> Result<SsoTokenResult, String> {
    let server_url = server_url.trim();
    let org_identifier = org_identifier.trim();
    let email = email.trim();

    if server_url.is_empty() {
        return Err("Server URL is required.".to_string());
    }
    if org_identifier.is_empty() {
        return Err("SSO organization identifier is required.".to_string());
    }

    let identity_base_url = resolve_identity_base_url(server_url)?;
    let api_base_url = resolve_api_base_url(server_url)?;
    let web_vault_url = resolve_web_vault_url(server_url)?;

    // Load or generate device key/identifier
    let (device_key, device_identifier) = match load_device_key(server_url) {
        Some(stored) => (Some(stored.key), stored.device_identifier),
        None => (None, Uuid::new_v4().to_string()),
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(25))
        .user_agent("bw-native/0.1.0")
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|error| format!("Failed to create HTTP client: {error}"))?;

    // Step 1: Prevalidate SSO
    let _sso_token = prevalidate_sso(&client, &identity_base_url, org_identifier)?;

    // Step 2: Generate PKCE parameters
    let code_verifier = generate_random_string(64);
    let code_challenge = generate_code_challenge(&code_verifier);
    let state = format!(
        "{}_identifier={}",
        generate_random_string(64),
        org_identifier
    );

    // Step 3: Start local callback server and get the port
    let (listener, port) = start_callback_server()?;
    let redirect_uri = format!("http://localhost:{port}");

    // Step 4: Build SSO URL and open the browser
    let authorize_url = build_authorize_url(
        &web_vault_url,
        &redirect_uri,
        &state,
        &code_challenge,
        org_identifier,
    );
    open_browser(&authorize_url)?;

    // Step 5: Wait for callback
    let callback = wait_for_callback(listener, &state)?;

    // Step 6: Exchange authorization code for tokens
    let token_url = format!("{identity_base_url}/connect/token");
    let token_form = [
        ("grant_type", "authorization_code".to_string()),
        ("code", callback.code),
        ("code_verifier", code_verifier),
        ("redirect_uri", redirect_uri),
        ("client_id", "desktop".to_string()),
        ("scope", "api offline_access".to_string()),
        ("deviceType", "8".to_string()),
        ("deviceIdentifier", device_identifier.clone()),
        ("deviceName", "bw-native".to_string()),
    ];

    let token_response = client
        .post(&token_url)
        .form(&token_form)
        .send()
        .map_err(|error| format!("SSO token exchange failed: {error}"))?;

    let status = token_response.status();
    let body = token_response.text().unwrap_or_default();

    if !status.is_success() {
        return Err(format!(
            "SSO login failed ({status}): {}",
            extract_error_message(&body)
        ));
    }

    let success: TokenSuccessResponse =
        from_str(&body).map_err(|error| format!("Invalid SSO token response: {error}"))?;

    let access_token = success
        .access_token
        .ok_or_else(|| "SSO response did not include an access token.".to_string())?;

    let protected_user_key = success.key.clone().unwrap_or_default();

    let kdf_config = KdfConfigSnapshot {
        kdf: success.kdf,
        iterations: success.kdf_iterations,
        memory: success.kdf_memory,
        parallelism: success.kdf_parallelism,
    };

    let has_master_password = success
        .user_decryption_options
        .as_ref()
        .map(|o| o.has_master_password)
        .unwrap_or(true);

    let tde_option = success
        .user_decryption_options
        .as_ref()
        .and_then(|o| o.trusted_device_option.clone());

    // ── Path 1: Master password ───────────────────────────────────────────────
    if has_master_password || (tde_option.is_none() && !protected_user_key.is_empty()) {
        return Ok(SsoTokenResult::NeedsMasterPassword {
            access_token,
            protected_user_key,
            api_base_url,
            kdf_config,
            client,
        });
    }

    // ── Path 2: TDE ───────────────────────────────────────────────────────────
    let tde = match tde_option {
        Some(t) => t,
        None => {
            return Ok(SsoTokenResult::NoDecryptionPath {
                message: "SSO login succeeded but vault decryption is not available. \
                          This account may use Key Connector or an unsupported configuration."
                    .to_string(),
            });
        }
    };

    // Sub-path 2a: device already trusted — decrypt directly.
    if let (Some(enc_private_key), Some(enc_user_key), Some(dk)) = (
        &tde.encrypted_private_key,
        &tde.encrypted_user_key,
        device_key,
    ) {
        match try_trusted_device_decrypt(
            &client,
            &api_base_url,
            &access_token,
            &dk,
            enc_private_key,
            enc_user_key,
        ) {
            Ok(login_result) => return Ok(SsoTokenResult::TrustedDeviceDecrypted(login_result)),
            Err(e) => {
                // Device key exists but decryption failed — fall through to
                // the auth-request path (key may have been rotated).
                eprintln!("Trusted device decrypt failed ({e}); falling back to auth request");
            }
        }
    }

    // Sub-path 2b: submit auth requests and wait for approval.
    let keypair = generate_ephemeral_keypair()?;
    let fingerprint = fingerprint_phrase(email, &keypair.public_key_b64);
    let access_code = generate_access_code();

    let mut auth_request_ids = Vec::new();

    // Try both auth-request types so either another device *or* an admin can approve.
    for request_type in [AUTH_REQUEST_TYPE_DEVICE, AUTH_REQUEST_TYPE_ADMIN] {
        match submit_auth_request(
            &client,
            &identity_base_url,
            &access_token,
            email,
            &keypair.public_key_b64,
            &device_identifier,
            &access_code,
            &fingerprint,
            request_type,
        ) {
            Ok(resp) => auth_request_ids.push(resp.id),
            Err(e) => eprintln!("Auth request (type {request_type}) failed: {e}"),
        }
    }

    if auth_request_ids.is_empty() {
        return Err("Could not submit auth approval request. \
             Check that your account has admin-approval or device-approval enabled."
            .to_string());
    }

    let ephemeral_private_key_der = private_key_to_der(&keypair.private_key)?;

    Ok(SsoTokenResult::NeedsDeviceApproval {
        pending: TdePendingState {
            access_token,
            api_base_url,
            identity_base_url,
            server_url: server_url.to_string(),
            email: email.to_string(),
            kdf_config,
            client,
            auth_request_ids,
            ephemeral_private_key_der,
            device_identifier,
        },
        fingerprint,
    })
}

// ── Trusted device decrypt ────────────────────────────────────────────────────

fn try_trusted_device_decrypt(
    client: &Client,
    api_base_url: &str,
    access_token: &str,
    device_key: &[u8; 32],
    encrypted_private_key: &str,
    encrypted_user_key: &str,
) -> Result<LoginResult, String> {
    // Decrypt the RSA private key with the device key
    let private_key_der = decrypt_with_device_key(device_key, encrypted_private_key)?;

    // Parse the RSA private key
    use rsa::pkcs8::DecodePrivateKey;
    let private_key = rsa::RsaPrivateKey::from_pkcs8_der(&private_key_der)
        .map_err(|e| format!("Failed to parse stored private key: {e}"))?;

    // Decrypt the user key with the RSA private key
    let user_key_bytes = rsa_decrypt_user_key(&private_key, encrypted_user_key)?;

    // The user key bytes are the raw 64-byte enc+mac key
    if user_key_bytes.len() != 64 {
        return Err(format!(
            "Unexpected user key length from TDE: {} bytes (expected 64)",
            user_key_bytes.len()
        ));
    }
    let mut user_key_arr = [0u8; 64];
    user_key_arr.copy_from_slice(&user_key_bytes);

    // Sync and decrypt vault using the raw user key bytes directly.
    let vault_view = sync_and_decrypt_vault_with_raw_user_key(
        client,
        api_base_url,
        access_token,
        &user_key_arr,
    )?;

    Ok(build_login_result(vault_view))
}

// ── Auth request ──────────────────────────────────────────────────────────────

fn submit_auth_request(
    client: &Client,
    identity_base_url: &str,
    access_token: &str,
    email: &str,
    public_key_b64: &str,
    device_identifier: &str,
    access_code: &str,
    fingerprint: &str,
    request_type: u32,
) -> Result<AuthRequestResponse, String> {
    let url = if request_type == AUTH_REQUEST_TYPE_ADMIN {
        format!("{identity_base_url}/auth-requests/admin-request")
    } else {
        format!("{identity_base_url}/auth-requests")
    };

    let body = CreateAuthRequest {
        email: email.to_string(),
        public_key: public_key_b64.to_string(),
        device_identifier: device_identifier.to_string(),
        access_code: access_code.to_string(),
        r#type: request_type,
        finger_print: fingerprint.to_string(),
    };

    let resp = client
        .post(&url)
        .bearer_auth(access_token)
        .json(&body)
        .send()
        .map_err(|e| format!("Auth request failed: {e}"))?;

    let status = resp.status();
    let text = resp.text().unwrap_or_default();
    if !status.is_success() {
        return Err(format!(
            "Auth request returned {status}: {}",
            extract_error_message(&text)
        ));
    }

    from_str(&text).map_err(|e| format!("Invalid auth request response: {e}"))
}

/// Poll all pending auth-request IDs once and return the first approved
/// encrypted user key found, along with the approving request's ID.
pub fn poll_auth_request_approval(pending: &TdePendingState) -> Result<Option<String>, String> {
    for request_id in &pending.auth_request_ids {
        let url = format!(
            "{}/auth-requests/{}/response",
            pending.identity_base_url, request_id
        );

        let resp = pending
            .client
            .get(&url)
            .bearer_auth(&pending.access_token)
            .send();

        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Auth request poll failed for {request_id}: {e}");
                continue;
            }
        };

        let status = resp.status();
        let text = resp.text().unwrap_or_default();

        if !status.is_success() {
            // 404 means not yet answered — normal during polling
            if status.as_u16() != 404 {
                eprintln!("Auth request poll {request_id} returned {status}: {text}");
            }
            continue;
        }

        let approval: AuthRequestApprovalResponse = match from_str(&text) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("Invalid approval response for {request_id}: {e}");
                continue;
            }
        };

        let is_approved =
            approval.approved.unwrap_or(false) || approval.request_approved.unwrap_or(false);

        if is_approved {
            if let Some(enc_user_key) = approval.encrypted_user_key {
                return Ok(Some(enc_user_key));
            }
        }
    }

    Ok(None)
}

/// Complete the TDE flow after an auth request has been approved.
/// Decrypts the user key, syncs the vault, and persists the device key.
pub fn complete_tde_after_approval(
    pending: &TdePendingState,
    encrypted_user_key: &str,
) -> Result<LoginResult, String> {
    // Reconstruct the ephemeral private key
    use rsa::pkcs8::DecodePrivateKey;
    let private_key = rsa::RsaPrivateKey::from_pkcs8_der(&pending.ephemeral_private_key_der)
        .map_err(|e| format!("Failed to reconstruct ephemeral private key: {e}"))?;

    // Decrypt the user key
    let user_key_bytes = rsa_decrypt_user_key(&private_key, encrypted_user_key)?;
    if user_key_bytes.len() != 64 {
        return Err(format!(
            "Unexpected user key length: {} bytes (expected 64)",
            user_key_bytes.len()
        ));
    }
    let mut user_key_arr = [0u8; 64];
    user_key_arr.copy_from_slice(&user_key_bytes);

    // Sync and decrypt vault
    let vault_view = sync_and_decrypt_vault_with_raw_user_key(
        &pending.client,
        &pending.api_base_url,
        &pending.access_token,
        &user_key_arr,
    )?;

    // Register this device as trusted
    if let Err(e) = register_device_trust(pending, &user_key_arr, &private_key) {
        // Non-fatal: log and continue — the user already has their vault.
        eprintln!("Warning: failed to register device trust: {e}");
    }

    Ok(build_login_result(vault_view))
}

// ── Device trust registration ─────────────────────────────────────────────────

fn register_device_trust(
    pending: &TdePendingState,
    user_key_arr: &[u8; 64],
    ephemeral_private_key: &rsa::RsaPrivateKey,
) -> Result<(), String> {
    // Generate a new permanent device key
    let new_device = generate_device_key();

    // Encrypt the user key with the ephemeral RSA public key (for the server
    // to echo back in future token responses' trustedDeviceOption)
    let rsa_pub = rsa::RsaPublicKey::from(ephemeral_private_key);
    let enc_user_key_b64 = rsa_encrypt(&rsa_pub, user_key_arr)?;
    let enc_user_key = format!("4.{enc_user_key_b64}");

    // Encode ephemeral public key as Base64 DER
    use rsa::pkcs8::EncodePublicKey;
    let pub_der = rsa_pub
        .to_public_key_der()
        .map_err(|e| format!("Failed to encode public key: {e}"))?;

    // Encrypt the RSA private key with the new device key
    let priv_der = private_key_to_der(ephemeral_private_key)?;
    let enc_private_key = encrypt_with_device_key(&new_device.key, &priv_der)?;

    // Encrypt the RSA public key with the user key
    let enc_public_key = encrypt_with_user_key_bytes(user_key_arr, pub_der.as_bytes())?;

    let trust_request = TrustDeviceRequest {
        name: "bw-native".to_string(),
        identifier: new_device.device_identifier.clone(),
        r#type: 8, // Linux desktop
        encrypted_user_key: enc_user_key,
        encrypted_public_key: enc_public_key,
        encrypted_private_key: enc_private_key,
    };

    let url = format!(
        "{}/devices/identifier/{}/trust",
        pending.api_base_url, pending.device_identifier
    );

    let resp = pending
        .client
        .put(&url)
        .bearer_auth(&pending.access_token)
        .json(&trust_request)
        .send()
        .map_err(|e| format!("Trust device request failed: {e}"))?;

    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().unwrap_or_default();
        return Err(format!(
            "Trust device returned {status}: {}",
            extract_error_message(&text)
        ));
    }

    // Persist the new device key locally
    save_device_key(
        &pending.server_url,
        &StoredDeviceKey {
            device_identifier: new_device.device_identifier,
            key: new_device.key,
        },
    )?;

    Ok(())
}

// ── Master password path ──────────────────────────────────────────────────────

/// After the SSO token exchange returns NeedsMasterPassword, call this to
/// decrypt the vault with the user's master password.
pub fn complete_sso_with_master_password(
    client: &Client,
    api_base_url: &str,
    access_token: &str,
    protected_user_key: &str,
    master_password: &str,
    email: &str,
    kdf_config: &KdfConfigSnapshot,
) -> Result<LoginResult, String> {
    let normalized_email = normalize_email(email);

    let prelogin = PreloginResponse {
        kdf: kdf_config.kdf,
        kdf_iterations: kdf_config.iterations,
        kdf_memory: kdf_config.memory,
        kdf_parallelism: kdf_config.parallelism,
    };
    let kdf = kdf_config_from_prelogin(&prelogin)?;
    let master_key = derive_master_key(master_password, &normalized_email, &kdf)?;

    let vault_view = sync_and_decrypt_vault(
        client,
        api_base_url,
        access_token,
        &master_key,
        protected_user_key,
    )?;

    Ok(build_login_result(vault_view))
}

// ── vault helpers ─────────────────────────────────────────────────────────────

fn sync_and_decrypt_vault_with_raw_user_key(
    client: &Client,
    api_base_url: &str,
    access_token: &str,
    user_key_bytes: &[u8; 64],
) -> Result<super::vault::DecryptedVaultView, String> {
    super::vault::sync_and_decrypt_vault_raw_key(client, api_base_url, access_token, user_key_bytes)
}

fn build_login_result(vault_view: super::vault::DecryptedVaultView) -> LoginResult {
    LoginResult {
        collections: vault_view.collections,
        items: vault_view
            .items
            .into_iter()
            .map(|item| VaultItemView {
                label: item.label,
                fields: item
                    .fields
                    .into_iter()
                    .map(|f| VaultItemFieldView {
                        label: f.label,
                        value: f.value,
                    })
                    .collect(),
            })
            .collect(),
    }
}

// ── SSO browser/callback helpers ──────────────────────────────────────────────

fn prevalidate_sso(
    client: &Client,
    identity_base_url: &str,
    org_identifier: &str,
) -> Result<String, String> {
    let url = format!(
        "{identity_base_url}/sso/prevalidate?domainHint={}",
        urlencoded(org_identifier)
    );

    let response = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .map_err(|error| format!("SSO prevalidation request failed: {error}"))?;

    let status = response.status();
    let body = response.text().unwrap_or_default();

    if !status.is_success() {
        return Err(format!(
            "SSO prevalidation failed ({status}): {}",
            extract_error_message(&body)
        ));
    }

    let parsed: SsoPreValidateResponse =
        from_str(&body).map_err(|error| format!("Invalid SSO prevalidation response: {error}"))?;

    parsed.token.filter(|t| !t.is_empty()).ok_or_else(|| {
        "SSO prevalidation succeeded but did not return a token. \
             Verify the organization identifier is correct."
            .to_string()
    })
}

fn generate_random_string(length: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut result = String::with_capacity(length);
    for _ in 0..length {
        let bytes = Uuid::new_v4();
        let byte_array = bytes.as_bytes();
        for &b in byte_array {
            if result.len() >= length {
                break;
            }
            result.push(CHARSET[(b as usize) % CHARSET.len()] as char);
        }
    }
    result.truncate(length);
    result
}

fn generate_code_challenge(code_verifier: &str) -> String {
    let hash = Sha256::digest(code_verifier.as_bytes());
    BASE64_URL_SAFE.encode(hash)
}

fn build_authorize_url(
    web_vault_url: &str,
    redirect_uri: &str,
    state: &str,
    code_challenge: &str,
    org_identifier: &str,
) -> String {
    format!(
        "{}/#/sso?\
         clientId=desktop\
         &redirectUri={}\
         &state={}\
         &codeChallenge={}\
         &identifier={}",
        web_vault_url.trim_end_matches('/'),
        urlencoded(redirect_uri),
        urlencoded(state),
        urlencoded(code_challenge),
        urlencoded(org_identifier),
    )
}

fn urlencoded(input: &str) -> String {
    let mut output = String::with_capacity(input.len() * 3);
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                output.push(byte as char);
            }
            _ => {
                output.push('%');
                output.push_str(&format!("{byte:02X}"));
            }
        }
    }
    output
}

fn start_callback_server() -> Result<(TcpListener, u16), String> {
    for port in SSO_PORT_START..=SSO_PORT_END {
        match TcpListener::bind(format!("127.0.0.1:{port}")) {
            Ok(listener) => {
                listener
                    .set_nonblocking(false)
                    .map_err(|e| format!("Failed to configure listener: {e}"))?;
                return Ok((listener, port));
            }
            Err(_) => continue,
        }
    }
    Err(format!(
        "Could not bind to any port in range {SSO_PORT_START}-{SSO_PORT_END}. \
         Close other applications using these ports and try again."
    ))
}

fn wait_for_callback(
    listener: TcpListener,
    expected_state: &str,
) -> Result<SsoCallbackResult, String> {
    listener
        .set_nonblocking(false)
        .map_err(|e| format!("Failed to configure listener: {e}"))?;

    let (tx, rx) = mpsc::channel();
    let expected_state = expected_state.to_string();

    let _handle = std::thread::spawn(move || match listener.accept() {
        Ok((mut stream, _)) => {
            let mut buf = [0u8; 4096];
            let n = match stream.read(&mut buf) {
                Ok(n) => n,
                Err(e) => {
                    let _ = tx.send(Err(format!("Failed to read from callback: {e}")));
                    return;
                }
            };

            let request = String::from_utf8_lossy(&buf[..n]);
            let result = parse_callback_request(&request, &expected_state);

            let (status_line, body) = match &result {
                Ok(_) => ("HTTP/1.1 200 OK", SSO_SUCCESS_HTML),
                Err(_) => ("HTTP/1.1 400 Bad Request", SSO_ERROR_HTML),
            };

            let response = format!(
                "{status_line}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
            let _ = tx.send(result);
        }
        Err(e) => {
            let _ = tx.send(Err(format!("Failed to accept callback connection: {e}")));
        }
    });

    rx.recv_timeout(SSO_CALLBACK_TIMEOUT)
        .map_err(|_| "SSO callback timed out after 5 minutes. Please try again.".to_string())?
}

fn parse_callback_request(
    request: &str,
    expected_state: &str,
) -> Result<SsoCallbackResult, String> {
    let first_line = request
        .lines()
        .next()
        .ok_or_else(|| "Empty callback request.".to_string())?;

    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err("Malformed callback request.".to_string());
    }

    let path = parts[1];
    let query_string = path.split_once('?').map(|(_, q)| q).unwrap_or("");

    let mut code = None;
    let mut state = None;

    for param in query_string.split('&') {
        let (key, value) = param.split_once('=').unwrap_or((param, ""));
        match key {
            "code" => code = Some(percent_decode(value)),
            "state" => state = Some(percent_decode(value)),
            _ => {}
        }
    }

    let code = code
        .filter(|c| !c.is_empty())
        .ok_or_else(|| "Callback did not include an authorization code.".to_string())?;
    let state = state
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Callback did not include state parameter.".to_string())?;

    if !check_state(&state, expected_state) {
        eprintln!("SSO state mismatch:\n  expected: {expected_state}\n  received: {state}");
        return Err("SSO callback state mismatch. This may indicate a security issue.".to_string());
    }

    Ok(SsoCallbackResult { code })
}

fn check_state(received: &str, expected: &str) -> bool {
    if received == expected {
        return true;
    }
    let received_id = extract_identifier_from_state(received);
    let expected_id = extract_identifier_from_state(expected);
    match (received_id, expected_id) {
        (Some(r), Some(e)) => r == e,
        _ => false,
    }
}

fn extract_identifier_from_state(state: &str) -> Option<&str> {
    state.split("_identifier=").nth(1).filter(|s| !s.is_empty())
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                    output.push((hi << 4) | lo);
                    i += 3;
                    continue;
                }
                output.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                output.push(b' ');
                i += 1;
            }
            other => {
                output.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8(output).unwrap_or_default()
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn open_browser(url: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let result = std::process::Command::new("open").arg(url).status();

    #[cfg(target_os = "linux")]
    let result = std::process::Command::new("xdg-open").arg(url).status();

    #[cfg(target_os = "windows")]
    let result = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!("Start-Process '{}'", url.replace('\'', "''")),
        ])
        .status();

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let result: Result<std::process::ExitStatus, std::io::Error> = Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Unsupported OS",
    ));

    result.map_err(|error| {
        format!(
            "Failed to open browser for SSO login: {error}. \
             Please manually open the SSO URL in your browser."
        )
    })?;

    Ok(())
}

const SSO_SUCCESS_HTML: &str = r#"<!DOCTYPE html>
<html>
<head><title>Bitwarden SSO</title></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #0a111d; color: #e6edf8;">
<div style="text-align: center;">
<h1 style="color: #45c287;">SSO Login Successful</h1>
<p>You can close this tab and return to bw-native.</p>
</div>
</body>
</html>"#;

const SSO_ERROR_HTML: &str = r#"<!DOCTYPE html>
<html>
<head><title>Bitwarden SSO</title></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #0a111d; color: #e6edf8;">
<div style="text-align: center;">
<h1 style="color: #ff6f86;">SSO Login Failed</h1>
<p>Something went wrong. Please close this tab and try again in bw-native.</p>
</div>
</body>
</html>"#;
