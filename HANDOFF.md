# Goal
Create a native Slint login UI for Bitwarden with:
- Server URL field (cloud or self-hosted)
- Username field
- Password field
- Functional login attempt when clicking `Log in`
- Vault sync + decryption after login

# Current Status
Completed:
- Slint login UI implemented.
- Login button wired to Rust handler.
- Bitwarden login flow implemented (`prelogin` -> KDF derivation -> `connect/token`).
- Post-login sync implemented (`/sync`).
- Vault decryption implemented for both:
  - Personal items (user key path)
  - Organization items (org key path, including asymmetric key handling)
- Cipher payload decryption implemented for top-level fields and `cipher.data` JSON payloads.
- Decrypted vault is printed to terminal for structure inspection.
- Code refactored out of `main.rs` into logical `ui/` and `auth/` modules.

Not completed:
- Rendering decrypted vault items in Slint UI.
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
    - identity + API URL resolution
    - `/accounts/prelogin` request
    - master key + password hash derivation
    - `/connect/token` request
    - post-login `/sync` + decrypt call
    - success/error handling
- `src/auth/crypto.rs`
  - KDF config parsing from prelogin response.
  - PBKDF2 and Argon2id key derivation.
  - Bitwarden-style password hash generation.
- `src/auth/server.rs`
  - Email normalization.
  - Identity endpoint resolution for cloud + self-hosted URLs.
  - API endpoint resolution for cloud + self-hosted URLs.
- `src/auth/errors.rs`
  - Error extraction/parsing from token responses.
- `src/auth/models.rs`
  - Request/response structs for prelogin and token handling (`access_token`, `key` parsing).
- `src/auth/vault.rs`
  - Sync and decrypt pipeline:
    - fetch `/sync`
    - decrypt protected user key using stretched master key
    - decrypt user private key
    - decrypt organization keys (including asymmetric encrypted key material types)
    - resolve per-item content keys (`cipher.key` when present)
    - decrypt top-level cipher fields and nested `cipher.data` JSON
    - decrypt collections/folders names
    - print decrypted vault JSON to terminal
- `Cargo.toml`
  - Added deps for auth/network/crypto/decrypt:
    - `reqwest` (blocking/json/rustls-tls)
    - `serde`, `serde_json`
    - `pbkdf2`, `argon2`, `sha1`, `sha2`, `base64`
    - `aes`, `cbc`, `hmac`, `rsa`
    - `uuid`

# Key Decisions
- Used direct HTTP + crypto implementation instead of `bitwarden` crate because the public crate is Secrets Manager-focused and not a stable high-level vault login SDK.
- Kept network/auth on a background thread to avoid blocking Slint UI.
- Kept `main.rs` minimal and moved logic into `ui/` and `auth/` folders for maintainability.
- Implemented Bitwarden-compatible HKDF stretch behavior for decrypting protected user key.
- Added organization decryption support using decrypted profile private key for asymmetric key material.

# Validation Run
Commands executed:
- `cargo check`

Result:
- Passed after UI/login implementation.
- Passed again after module refactors.
- Passed after sync/decryption additions and subsequent fixes.

# Remaining Work
1. Implement a method for rendering decrypted vault items in the Slint UI.
2. Remove temporary sensitive debug logging from auth flow before broader use.
3. Add 2FA flow (provider selection + code input + retry token request with 2FA params).
4. Persist server URL and username between launches.
5. Store access/refresh token securely and wire post-login app flow.
6. Add tests for:
   - sync/decryption key hierarchy (user/org/item key resolution)
   - asymmetric org key decryption path
   - `resolve_identity_base_url`
   - `resolve_api_base_url`
   - KDF selection + derivation paths
   - error message parsing

# Known Risks / Edge Cases
- Current flow does not provide an explicit 2FA prompt; users requiring 2FA will see server errors in status text.
- Identity URL resolution for unusual self-hosted path setups may need adjustment.
- API URL resolution for unusual self-hosted path setups may need adjustment.
- KDF defaults are defensive but should ideally always match server-returned values.
- Decryption currently targets observed field structures and may need expansion for additional vault object variants.
