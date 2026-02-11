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
  - Right: read-only selected-item details form
- Collections are grouped into a collapsible tree (expand/collapse on click), built from slash-separated collection paths.
- Vault item selection implemented:
  - Clicking an item in the middle list updates the right-hand details panel.
  - Selected item is highlighted in the middle list.
- Vault details panel implemented:
  - Renders non-empty decrypted fields from `cipher.data` as structured label/value rows.
  - Field order is prioritized as Username, Password, TOTP, then other fields.
  - `Name` is removed from field rows and shown only as the panel title.
  - Password row supports reveal/hide toggle.
  - TOTP row renders rolling code from stored seed (raw Base32 or `otpauth://` URI).
  - TOTP display refreshes automatically on a 1-second timer.

Not completed:
- Dedicated 2FA challenge UI flow.
- Session/token persistence after successful login.
- Dark mode and visual polish pass for the interface.

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
    - `vault-item-rows`
    - `selected-vault-item-fields`
  - Added callback:
    - `collection-tree-row-clicked(int)`
    - `vault-item-clicked(int)`
    - `toggle-password-visibility()`
  - Added `CollectionTreeRow` struct for tree row rendering metadata.
  - Added `VaultItemRow` and `VaultItemFieldRow` structs.
  - Added vault layout with 3 horizontal sections:
    - fixed-width left collections section
    - fixed-width middle vault items section
    - flexible right details section with read-only form cards
  - Added selected item state properties:
    - `selected-vault-item-index`
    - `selected-vault-item-title`
    - `selected-vault-item-empty-text`
    - `selected-has-password`
    - `is-password-visible`
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
  - Added selected vault item state management and click handling.
  - Added password masking/reveal behavior for password field rows.
  - Added TOTP generation and live refresh pipeline:
    - Parses raw Base32 secrets and `otpauth://` URIs.
    - Supports SHA1/SHA256/SHA512, configurable digits/period from URI.
    - Computes rolling codes and updates selected row values every second.
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
  - Returns structured login result with decrypted collection list + structured item field data for UI.
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
    - `items: Vec<DecryptedVaultItem>`
  - Added `DecryptedVaultItem` and `DecryptedVaultField` for structured details output.
  - Added extraction helpers for:
    - collection names
    - item names for list labels
    - non-empty decrypted `cipher.data` fields for details rendering
  - Added field-label prettification and deterministic field ordering.
  - Added filter to omit `Name` from details fields.
  - Added unit tests for label formatting and ordering/filter behavior.
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
- Chose structured details models (field rows) instead of raw JSON text rendering for right-hand item details.
- Defaulted password to masked display with explicit reveal toggle.
- Implemented TOTP computation client-side from decrypted seed values so the UI shows live codes instead of raw secrets.

# Validation Run
Commands executed:
- `cargo check`
- `cargo test --quiet`

Result:
- Passed after UI/login implementation.
- Passed again after module refactors.
- Passed after sync/decryption additions and subsequent fixes.
- Passed after introducing vault rendering models and list binding.
- Passed after converting to single-window multi-view layout.
- Passed after adding collapsible collection tree state and callbacks.
- Passed after adding selectable details form panel.
- Passed after adding password reveal toggle and field ordering.
- Passed after adding rolling TOTP rendering and tests.

# Remaining Work
1. Implement dark mode and polish the visual design of login + vault views (colors, spacing, typography, and component styling consistency).
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
   - TOTP edge cases (invalid seeds, URI variants, non-30-second periods)

# Known Risks / Edge Cases
- Current flow does not provide an explicit 2FA prompt; users requiring 2FA will see server errors in status text.
- Identity URL resolution for unusual self-hosted path setups may need adjustment.
- API URL resolution for unusual self-hosted path setups may need adjustment.
- KDF defaults are defensive but should ideally always match server-returned values.
- Decryption currently targets observed field structures and may need expansion for additional vault object variants.
- Some vault types may have sparse/non-standard `cipher.data` layouts, so details panel field coverage may need per-type tuning.
- TOTP rendering assumes standard Base32/otpauth formats; malformed secrets currently fall back to raw value display.
