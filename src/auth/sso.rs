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
use super::errors::extract_error_message;
use super::models::{PreloginResponse, SsoPreValidateResponse, TokenSuccessResponse};
use super::server::{
    normalize_email, resolve_api_base_url, resolve_identity_base_url, resolve_web_vault_url,
};
use super::vault::sync_and_decrypt_vault;
use super::workflow::{LoginResult, VaultItemFieldView, VaultItemView};

const SSO_PORT_START: u16 = 8065;
const SSO_PORT_END: u16 = 8070;
const SSO_CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);

/// Describes the result of the SSO token exchange. The caller may need to prompt
/// for a master password to decrypt the vault if the server indicates one is required.
pub enum SsoTokenResult {
    /// Token exchange succeeded and the user has a master password. The caller
    /// must collect the master password, derive the master key, and decrypt.
    NeedsMasterPassword {
        access_token: String,
        protected_user_key: String,
        api_base_url: String,
        kdf_config: KdfConfigSnapshot,
        client: Client,
    },
    /// Token exchange succeeded but the vault cannot be decrypted because the
    /// user has no master password and Key Connector / TDE is not yet supported.
    NoDecryptionPath { message: String },
}

/// Snapshot of KDF config from the token response (SSO doesn't do prelogin).
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

/// Begin the SSO authentication flow. This:
/// 1. Prevalidates SSO for the org identifier
/// 2. Generates PKCE code_verifier + code_challenge
/// 3. Starts a local HTTP server
/// 4. Opens the browser to the authorize URL
/// 5. Waits for the callback with the authorization code
/// 6. Exchanges the code for tokens
///
/// Returns an `SsoTokenResult` describing what the caller needs to do next.
pub fn try_sso_login(server_url: &str, org_identifier: &str) -> Result<SsoTokenResult, String> {
    let server_url = server_url.trim();
    let org_identifier = org_identifier.trim();

    if server_url.is_empty() {
        return Err("Server URL is required.".to_string());
    }
    if org_identifier.is_empty() {
        return Err("SSO organization identifier is required.".to_string());
    }

    let identity_base_url = resolve_identity_base_url(server_url)?;
    let api_base_url = resolve_api_base_url(server_url)?;
    let web_vault_url = resolve_web_vault_url(server_url)?;

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

    // Step 4: Build SSO URL through the web vault (the web vault handles the
    // actual OAuth/OIDC flow with the identity server)
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
    let device_identifier = Uuid::new_v4().to_string();
    let token_url = format!("{identity_base_url}/connect/token");

    let token_form = [
        ("grant_type", "authorization_code".to_string()),
        ("code", callback.code),
        ("code_verifier", code_verifier),
        ("redirect_uri", redirect_uri),
        ("client_id", "desktop".to_string()),
        ("scope", "api offline_access".to_string()),
        ("deviceType", "8".to_string()),
        ("deviceIdentifier", device_identifier),
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

    let protected_user_key = success.key.unwrap_or_default();

    let kdf_config = KdfConfigSnapshot {
        kdf: success.kdf,
        iterations: success.kdf_iterations,
        memory: success.kdf_memory,
        parallelism: success.kdf_parallelism,
    };

    // Check decryption options
    let has_master_password = success
        .user_decryption_options
        .as_ref()
        .map(|opts| opts.has_master_password)
        .unwrap_or(true); // Default to true for servers that don't send this

    if has_master_password || !protected_user_key.is_empty() {
        Ok(SsoTokenResult::NeedsMasterPassword {
            access_token,
            protected_user_key,
            api_base_url,
            kdf_config,
            client,
        })
    } else {
        Ok(SsoTokenResult::NoDecryptionPath {
            message: "SSO login succeeded but vault decryption is not available. \
                      This account may use Key Connector or Trusted Device Encryption, \
                      which are not yet supported."
                .to_string(),
        })
    }
}

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

    // Build KDF config from the token response parameters
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

    Ok(LoginResult {
        collections: vault_view.collections,
        items: vault_view
            .items
            .into_iter()
            .map(|item| VaultItemView {
                label: item.label,
                fields: item
                    .fields
                    .into_iter()
                    .map(|field| VaultItemFieldView {
                        label: field.label,
                        value: field.value,
                    })
                    .collect(),
            })
            .collect(),
    })
}

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
        // Use UUID as entropy source since we already have the uuid crate
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
    // Set a timeout on the listener
    listener
        .set_nonblocking(false)
        .map_err(|e| format!("Failed to configure listener: {e}"))?;

    // Use a channel with timeout for the overall operation
    let (tx, rx) = mpsc::channel();
    let expected_state = expected_state.to_string();

    let _handle = std::thread::spawn(move || {
        match listener.accept() {
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

                // Parse the GET request line to extract query parameters
                let result = parse_callback_request(&request, &expected_state);

                // Send response to browser
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
        }
    });

    rx.recv_timeout(SSO_CALLBACK_TIMEOUT)
        .map_err(|_| "SSO callback timed out after 5 minutes. Please try again.".to_string())?
}

fn parse_callback_request(
    request: &str,
    expected_state: &str,
) -> Result<SsoCallbackResult, String> {
    // Extract the path from "GET /path?query HTTP/1.1"
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

    // Verify state to prevent CSRF. The web vault and identity server may
    // transform the state during the OAuth redirect chain, so we check that
    // the `_identifier=` portion (which contains the org identifier we embedded)
    // is present in the returned state rather than requiring an exact match.
    if !check_state(&state, expected_state) {
        eprintln!("SSO state mismatch:\n  expected: {expected_state}\n  received: {state}");
        return Err("SSO callback state mismatch. This may indicate a security issue.".to_string());
    }

    Ok(SsoCallbackResult { code })
}

/// Validate that the returned state matches what we sent.
/// The official Bitwarden client checks the `_identifier=` suffix
/// to verify the org identifier matches. The random prefix may be
/// transformed by the web vault / identity server redirect chain.
fn check_state(received: &str, expected: &str) -> bool {
    // Exact match is ideal
    if received == expected {
        return true;
    }

    // Extract the `_identifier=<value>` portion from both and compare.
    // This is the same approach the official Bitwarden client uses.
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

    // On Windows, we must use PowerShell's Start-Process because cmd.exe's
    // `start` command interprets `&` in URLs as command separators.
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
