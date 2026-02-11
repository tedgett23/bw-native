# Goal
Create a native Slint login UI for Bitwarden with:
- Server URL field (cloud or self-hosted)
- Username field
- Password field
- Functional login attempt when clicking `Log in`

# Current Status
Completed:
- Slint login UI implemented.
- Login button wired to Rust handler.
- Bitwarden login flow implemented (`prelogin` -> KDF derivation -> `connect/token`).
- Code refactored out of `main.rs` into logical `ui/` and `auth/` modules.

Not completed:
- Dedicated 2FA challenge UI flow.
- Session/token persistence after successful login.

# Changes Made
- `ui/app-window.slint`
  - Replaced placeholder UI with Bitwarden login form.
  - Added properties: `server-url`, `username`, `password`, `status-text`, `status-is-error`, `is-logging-in`.
  - Added callback: `login-requested()`.
  - Added status text display and loading/disabled states.
- `src/main.rs`
  - Reduced to entrypoint only (`ui::run()`), module declarations, and Slint include.
- `src/ui/mod.rs`
  - UI bootstrap: create `MainWindow`, attach handlers, run window.
- `src/ui/login_controller.rs`
  - Login button callback handling.
  - Spawns background thread for network/auth work.
  - Uses `slint::invoke_from_event_loop` to update UI state safely.
- `src/auth/mod.rs`
  - Auth module root; re-exports `try_login`.
- `src/auth/workflow.rs`
  - Main login workflow:
    - input validation
    - identity URL resolution
    - `/accounts/prelogin` request
    - master key + password hash derivation
    - `/connect/token` request
    - success/error handling
- `src/auth/crypto.rs`
  - KDF config parsing from prelogin response.
  - PBKDF2 and Argon2id key derivation.
  - Bitwarden-style password hash generation.
- `src/auth/server.rs`
  - Email normalization.
  - Identity endpoint resolution for cloud + self-hosted URLs.
- `src/auth/errors.rs`
  - Error extraction/parsing from token responses.
- `src/auth/models.rs`
  - Request/response structs for prelogin and token handling.
- `Cargo.toml`
  - Added deps for auth/network/crypto:
    - `reqwest` (blocking/json/rustls-tls)
    - `serde`, `serde_json`
    - `pbkdf2`, `argon2`, `sha2`, `base64`
    - `uuid`

# Key Decisions
- Used direct HTTP + crypto implementation instead of `bitwarden` crate because the public crate is Secrets Manager-focused and not a stable high-level vault login SDK.
- Kept network/auth on a background thread to avoid blocking Slint UI.
- Kept `main.rs` minimal and moved logic into `ui/` and `auth/` folders for maintainability.

# Validation Run
Commands executed:
- `cargo check`

Result:
- Passed after UI/login implementation.
- Passed again after module refactors.

# Remaining Work
1. Add 2FA flow (provider selection + code input + retry token request with 2FA params).
2. Persist server URL and username between launches.
3. Store access/refresh token securely and wire post-login app flow.
4. Add tests for:
   - `resolve_identity_base_url`
   - KDF selection + derivation paths
   - error message parsing

# Known Risks / Edge Cases
- Current flow does not provide an explicit 2FA prompt; users requiring 2FA will see server errors in status text.
- Identity URL resolution for unusual self-hosted path setups may need adjustment.
- KDF defaults are defensive but should ideally always match server-returned values.
