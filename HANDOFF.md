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
- Decrypted vault data is transformed into UI-ready models and rendered in Slint.
- Code refactored out of `main.rs` into logical `ui/` and `auth/` modules.
- App now uses a single `MainWindow` with in-window view switching:
  - Login view
  - Vault view
- Vault view now has three horizontal sections:
  - Left: collections tree
  - Middle: vault items list
  - Right: empty placeholder panel for details
- Collections are grouped into a collapsible tree (expand/collapse on click), built from slash-separated collection paths.

Not completed:
- Dedicated 2FA challenge UI flow.
- Session/token persistence after successful login.
- Vault item details panel behavior (click item in middle list -> render full item contents in right section).

# Changes Made
- `ui/app-window.slint`
  - Replaced placeholder UI with Bitwarden login form.
  - Added properties: `server-url`, `username`, `password`, `status-text`, `status-is-error`, `is-logging-in`.
  - Added callback: `login-requested()`.
  - Added status text display and loading/disabled states.
  - Added in-window view state:
    - `is-vault-view`
  - Added vault models:
    - `collection-tree-rows`
    - `vault-items`
  - Added callback:
    - `collection-tree-row-clicked(int)`
  - Added `CollectionTreeRow` struct for tree row rendering metadata.
  - Added vault layout with 3 horizontal sections:
    - fixed-width left collections section
    - fixed-width middle vault items section
    - flexible empty right section
- `src/main.rs`
  - Reduced to entrypoint only (`ui::run()`), module declarations, and Slint include.
- `src/ui/mod.rs`
  - UI bootstrap: create `MainWindow`, attach handlers, run window.
- `src/ui/login_controller.rs`
  - Login button callback handling.
  - Spawns background thread for network/auth work.
  - Uses `slint::invoke_from_event_loop` to update UI state safely.
  - Switched to single-window transition by toggling `is-vault-view`.
  - Populates vault item model after successful login.
  - Added collection tree state management:
    - path-to-tree build
    - flattened visible rows
    - expand/collapse toggle handling
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
  - Returns structured login result with decrypted collection and item summary lists for UI.
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
  - Added `DecryptedVaultView` output with:
    - `collections: Vec<String>`
    - `items: Vec<String>`
  - Added summary extraction helpers for collection names and vault item labels.
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
- Chose a single window with conditional views rather than opening a second window instance, to preserve size/position during login -> vault transition.
- Implemented collection navigation as a client-side tree model derived from collection path segments.

# Validation Run
Commands executed:
- `cargo check`

Result:
- Passed after UI/login implementation.
- Passed again after module refactors.
- Passed after sync/decryption additions and subsequent fixes.
- Passed after introducing vault rendering models and list binding.
- Passed after converting to single-window multi-view layout.
- Passed after adding collapsible collection tree state and callbacks.

# Remaining Work
1. Implement vault item selection behavior:
   - click a vault item in the middle section
   - render full decrypted vault item contents in the far-right section
2. Add 2FA flow (provider selection + code input + retry token request with 2FA params).
3. Persist server URL and username between launches.
4. Store access/refresh token securely and wire post-login app flow.
5. Add tests for:
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
- Vault item list currently shows summary labels only; detail projection and field formatting rules for the right-hand details panel are not implemented yet.
