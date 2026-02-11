use std::time::Duration;

use reqwest::blocking::Client;
use serde_json::from_str;
use uuid::Uuid;

use super::crypto::{derive_master_key, derive_password_hash, kdf_config_from_prelogin};
use super::errors::extract_error_message;
use super::models::{PreloginRequest, PreloginResponse, TokenSuccessResponse};
use super::server::{normalize_email, resolve_api_base_url, resolve_identity_base_url};
use super::vault::sync_and_print_vault;

pub fn try_login(server_url: &str, username: &str, password: &str) -> Result<(), String> {
    let server_url = server_url.trim();
    let username = username.trim();
    let password = password.trim();

    if server_url.is_empty() {
        return Err("Server URL is required.".to_string());
    }
    if username.is_empty() {
        return Err("Username is required.".to_string());
    }
    if password.is_empty() {
        return Err("Password is required.".to_string());
    }

    let normalized_email = normalize_email(username);
    let identity_base_url = resolve_identity_base_url(server_url)?;
    let api_base_url = resolve_api_base_url(server_url)?;

    let client = Client::builder()
        .timeout(Duration::from_secs(25))
        .user_agent("bw-native/0.1.0")
        .build()
        .map_err(|error| format!("Failed to create HTTP client: {error}"))?;

    let prelogin_url = format!("{identity_base_url}/accounts/prelogin");
    let prelogin_response = client
        .post(prelogin_url)
        .json(&PreloginRequest {
            email: &normalized_email,
        })
        .send()
        .map_err(|error| format!("Prelogin request failed: {error}"))?;

    if !prelogin_response.status().is_success() {
        let status = prelogin_response.status();
        let body = prelogin_response.text().unwrap_or_default();
        return Err(format!(
            "Prelogin failed ({status}): {}",
            extract_error_message(&body)
        ));
    }

    let prelogin_data: PreloginResponse = prelogin_response
        .json()
        .map_err(|error| format!("Invalid prelogin response: {error}"))?;

    let kdf = kdf_config_from_prelogin(&prelogin_data)?;
    let master_key = derive_master_key(password, &normalized_email, &kdf)?;
    let password_hash = derive_password_hash(password, &master_key);

    let token_url = format!("{identity_base_url}/connect/token");
    let device_identifier = Uuid::new_v4().to_string();
    let token_form = [
        ("grant_type", "password".to_string()),
        ("client_id", "web".to_string()),
        ("scope", "api offline_access".to_string()),
        ("username", username.to_string()),
        ("password", password_hash),
        ("deviceType", "8".to_string()),
        ("deviceIdentifier", device_identifier),
        ("deviceName", "bw-native".to_string()),
    ];

    let token_response = client
        .post(token_url)
        .form(&token_form)
        .send()
        .map_err(|error| format!("Token request failed: {error}"))?;

    let status = token_response.status();
    let body = token_response.text().unwrap_or_default();

    println!("===== Token Response ({status}) =====");
    println!("{body}");
    println!("===== End Token Response =====");

    if !status.is_success() {
        return Err(format!(
            "Login failed ({status}): {}",
            extract_error_message(&body)
        ));
    }

    let success: TokenSuccessResponse =
        from_str(&body).map_err(|error| format!("Invalid token response: {error}"))?;

    let access_token = success
        .access_token
        .ok_or_else(|| "Login response did not include an access token.".to_string())?;
    let protected_user_key = success
        .key
        .ok_or_else(|| "Login response did not include the encrypted user key.".to_string())?;

    println!(
        "Token parse summary: access_token_present=true key_present=true key_len={}",
        protected_user_key.len()
    );

    sync_and_print_vault(
        &client,
        &api_base_url,
        &access_token,
        &master_key,
        &protected_user_key,
    )?;

    Ok(())
}
