use reqwest::Url;

pub(super) fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Resolves the web vault base URL from the user-provided server URL.
/// For official Bitwarden servers, this is `https://vault.bitwarden.com`.
/// For self-hosted servers, this is typically the server URL itself.
pub(super) fn resolve_web_vault_url(server_url: &str) -> Result<String, String> {
    let mut parsed = Url::parse(server_url).map_err(|error| {
        format!("Server URL is invalid ({error}). Example: https://vault.bitwarden.com")
    })?;
    parsed.set_query(None);
    parsed.set_fragment(None);

    let scheme = parsed.scheme().to_string();
    let host = parsed
        .host_str()
        .ok_or_else(|| "Server URL must include a host.".to_string())?
        .to_ascii_lowercase();
    let port = parsed
        .port()
        .map(|value| format!(":{value}"))
        .unwrap_or_default();

    if matches!(
        host.as_str(),
        "vault.bitwarden.com" | "api.bitwarden.com" | "identity.bitwarden.com" | "bitwarden.com"
    ) {
        return Ok(format!("{scheme}://vault.bitwarden.com{port}"));
    }

    if matches!(
        host.as_str(),
        "vault.bitwarden.eu" | "api.bitwarden.eu" | "identity.bitwarden.eu" | "bitwarden.eu"
    ) {
        return Ok(format!("{scheme}://vault.bitwarden.eu{port}"));
    }

    // For self-hosted, strip any /api or /identity suffix and return the base
    let mut base = parsed.to_string().trim_end_matches('/').to_string();
    for suffix in &["/identity", "/api"] {
        if base.ends_with(suffix) {
            base.truncate(base.len() - suffix.len());
            break;
        }
    }

    Ok(base)
}

pub(super) fn resolve_identity_base_url(server_url: &str) -> Result<String, String> {
    let mut parsed = Url::parse(server_url).map_err(|error| {
        format!("Server URL is invalid ({error}). Example: https://vault.bitwarden.com")
    })?;
    parsed.set_query(None);
    parsed.set_fragment(None);

    let scheme = parsed.scheme().to_string();
    let host = parsed
        .host_str()
        .ok_or_else(|| "Server URL must include a host.".to_string())?
        .to_ascii_lowercase();
    let port = parsed
        .port()
        .map(|value| format!(":{value}"))
        .unwrap_or_default();

    if matches!(
        host.as_str(),
        "vault.bitwarden.com" | "api.bitwarden.com" | "bitwarden.com"
    ) {
        return Ok(format!("{scheme}://identity.bitwarden.com{port}"));
    }

    if matches!(
        host.as_str(),
        "vault.bitwarden.eu" | "api.bitwarden.eu" | "bitwarden.eu"
    ) {
        return Ok(format!("{scheme}://identity.bitwarden.eu{port}"));
    }

    if host.starts_with("identity.") {
        return Ok(format!("{scheme}://{host}{port}"));
    }

    let mut path = parsed.path().trim_end_matches('/').to_string();
    if path.is_empty() {
        path = "/identity".to_string();
    } else if !path.ends_with("/identity") {
        path.push_str("/identity");
    }

    parsed.set_path(&path);
    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

pub(super) fn resolve_api_base_url(server_url: &str) -> Result<String, String> {
    let mut parsed = Url::parse(server_url).map_err(|error| {
        format!("Server URL is invalid ({error}). Example: https://vault.bitwarden.com")
    })?;
    parsed.set_query(None);
    parsed.set_fragment(None);

    let scheme = parsed.scheme().to_string();
    let host = parsed
        .host_str()
        .ok_or_else(|| "Server URL must include a host.".to_string())?
        .to_ascii_lowercase();
    let port = parsed
        .port()
        .map(|value| format!(":{value}"))
        .unwrap_or_default();

    if matches!(
        host.as_str(),
        "vault.bitwarden.com" | "identity.bitwarden.com" | "bitwarden.com"
    ) {
        return Ok(format!("{scheme}://api.bitwarden.com{port}"));
    }

    if matches!(
        host.as_str(),
        "vault.bitwarden.eu" | "identity.bitwarden.eu" | "bitwarden.eu"
    ) {
        return Ok(format!("{scheme}://api.bitwarden.eu{port}"));
    }

    if host.starts_with("api.") {
        return Ok(format!("{scheme}://{host}{port}"));
    }

    let mut path = parsed.path().trim_end_matches('/').to_string();
    if path.is_empty() {
        path = "/api".to_string();
    } else if !path.ends_with("/api") {
        path.push_str("/api");
    }

    parsed.set_path(&path);
    Ok(parsed.to_string().trim_end_matches('/').to_string())
}
