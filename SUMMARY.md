# bw-native — Codebase Summary

A native Bitwarden vault client built in Rust using [Slint](https://slint.dev/) for the UI. It supports logging in to official Bitwarden servers (cloud and EU), Vaultwarden, and generic self-hosted instances. The app syncs and decrypts the full vault client-side (zero-knowledge), then presents it in a three-panel dark-themed desktop UI with collection browsing, item search, and live TOTP code generation.

**Current state:** Read-only. The app can authenticate (password login, SSO with master password, or SSO with Trusted Device Encryption), sync, and display vault contents but cannot create, edit, or delete items.

---

## Project Structure

```
bw-native/
├── Cargo.toml                  # Dependencies and project metadata (edition 2024)
├── build.rs                    # Compiles Slint UI files at build time
├── src/
│   ├── main.rs                 # Entry point; OpenGL → software renderer fallback
│   ├── auth/                   # Authentication, crypto, and vault logic
│   │   ├── mod.rs              # Exports try_login, try_sso_login, complete_sso_with_master_password, complete_tde_after_approval, poll_auth_request_approval
│   │   ├── models.rs           # Serde models for Bitwarden API requests/responses
│   │   ├── errors.rs           # User-friendly error extraction from API responses
│   │   ├── crypto.rs           # KDF key derivation (PBKDF2, Argon2id)
│   │   ├── server.rs           # URL normalization and endpoint resolution (identity, API, web vault)
│   │   ├── sso.rs              # SSO authentication (PKCE, local callback server, token exchange, TDE)
│   │   ├── device_trust.rs     # TDE: device key storage, RSA keypair generation, AES/RSA crypto helpers
│   │   ├── vault.rs            # Vault sync, multi-layer decryption, data extraction (~1,020 lines)
│   │   └── workflow.rs         # High-level password login orchestration
│   └── ui/                     # Slint ↔ Rust glue
│       ├── mod.rs              # Creates MainWindow and starts event loop
│       └── login_controller.rs # All UI event handlers, TOTP generation, search, TDE polling (~1,500 lines)
└── ui/
    └── app-window.slint        # Complete UI definition (login + SSO + TDE approval + vault views, ~700 lines)
```

**~3,900 lines of code total.**

---

## Architecture

### Layered Design

```
┌─────────────────────────────────────────────┐
│  UI Layer — Slint (ui/app-window.slint)     │  Declarative markup, dark theme, reactive
├─────────────────────────────────────────────┤
│  Controller — login_controller.rs           │  Event handlers, state, threading, TDE polling
├─────────────────────────────────────────────┤
│  Business Logic — workflow.rs + sso.rs      │  Login flow orchestration
├─────────────────────────────────────────────┤
│  Infrastructure — crypto, vault, server     │  HTTP, crypto, decryption, parsing
└─────────────────────────────────────────────┘
```

### Key Patterns

- **Public entry points:** `auth::try_login(server_url, username, password)` for password login, `auth::try_sso_login(server_url, org_identifier, email)` for SSO (returns an enum describing the required next step), `auth::complete_sso_with_master_password(...)` for vault decryption after SSO with master password, `auth::complete_tde_after_approval(...)` for vault decryption after TDE auth-request approval.
- **Threading:** Slint runs on the main thread. Blocking network I/O runs on a background `std::thread`. Cross-thread UI updates use `slint::invoke_from_event_loop`.
- **Shared state:** `Arc<Mutex<T>>` wrappers for collection tree state, vault items, visible indices, password visibility, active collection filter, SSO pending state, and TDE pending state.
- **Error handling:** `Result<T, String>` throughout with contextual error messages. API errors are parsed to extract user-friendly messages.
- **Renderer fallback:** `main.rs` catches panics/errors from Slint initialization and relaunches the process with `SLINT_BACKEND=winit-software` if hardware rendering fails.

---

## Authentication & Vault Flow

### Password Login

```
User enters server URL, email, password
  │
  ├─ 1. Resolve endpoints (server.rs)
  │     vault.bitwarden.com → identity.bitwarden.com + api.bitwarden.com
  │     self-hosted → append /identity and /api paths
  │
  ├─ 2. Prelogin  (POST /identity/accounts/prelogin)
  │     → Returns KDF params (PBKDF2 or Argon2id configuration)
  │
  ├─ 3. Key derivation (crypto.rs)
  │     email + password → master_key (32 bytes)
  │     master_key + password → password_hash (for auth only)
  │
  ├─ 4. Token request  (POST /identity/connect/token)
  │     OAuth2 password grant, client_id="web", deviceType="8"
  │     → access_token + encrypted user key
  │
  ├─ 5. Vault sync  (GET /api/sync?excludeDomains=true)
  │     Bearer token auth → full encrypted vault JSON
  │
  └─ 6. Multi-layer decryption (vault.rs)
        master_key → user_key → org_keys → per-item keys
        Decrypt: collections, folders, ciphers (login, card, identity, etc.)
        Extract and flatten fields into label/value pairs
```

### SSO Login (sso.rs)

```
User enters server URL, email, and SSO org identifier
  │
  ├─ 1. Resolve endpoints (server.rs)
  │
  ├─ 2. Prevalidate SSO  (GET /identity/sso/prevalidate?domainHint={identifier})
  │
  ├─ 3. Generate PKCE parameters + start local HTTP callback server (ports 8065-8070)
  │
  ├─ 4. Open browser to web vault SSO page; user completes SSO + 2FA
  │
  ├─ 5. Receive callback; exchange code for tokens
  │     POST /identity/connect/token
  │     → access_token + UserDecryptionOptions + optional trustedDeviceOption
  │
  └─ 6. Determine decryption path from UserDecryptionOptions:
        a) hasMasterPassword=true  → NeedsMasterPassword  (prompt for master password)
        b) trustedDeviceOption present, device key on disk → TrustedDeviceDecrypted (auto-decrypt)
        c) trustedDeviceOption present, no device key     → NeedsDeviceApproval (auth request flow)
        d) neither                 → NoDecryptionPath (unsupported)
```

### Trusted Device Encryption (sso.rs + device_trust.rs)

```
Path b — Already trusted device:
  ├─ Load device key from ~/.config/bw-native/device_key.json
  ├─ Decrypt encryptedPrivateKey (from trustedDeviceOption) with device key (AES-256-CBC + HMAC)
  ├─ Decrypt encryptedUserKey with RSA private key (OAEP-SHA1)
  └─ Use raw 64-byte user key to sync and decrypt vault directly

Path c — New device (needs approval):
  ├─ Generate ephemeral RSA-2048 keypair + 25-char access code
  ├─ Compute fingerprint phrase (5 words, shown to approver for verification)
  ├─ POST /api/auth-requests          (type 0, unauthenticated — device approval)
  ├─ POST /api/auth-requests/admin-request  (type 2, bearer token — admin approval)
  ├─ Show "Approve from Another Device" UI with fingerprint
  ├─ Poll every 10 seconds:
  │   Device approval: GET /api/auth-requests/{id}/response?code={access_code}  (no auth)
  │   Admin approval:  GET /api/auth-requests/{id}  (bearer token)
  ├─ On approval: RSA-decrypt user key from response
  ├─ Sync and decrypt vault with user key
  └─ Register device trust (PUT /api/devices/identifier/{new_id}/trust)
        Generates new permanent device key
        Encrypts: private key with device key, public key with user key, user key with RSA public key
        Persists device key to ~/.config/bw-native/device_key.json
        Future logins on this device will use Path b (auto-decrypt)

Path a — Master password:
  └─ Same as password login steps 3–6 above (derive master key, decrypt vault)
```

### Cryptographic Details (vault.rs + device_trust.rs)

- **Key hierarchy:** Master Key → User Key (AES-CBC decryption) → Organization Keys (via user key or RSA private key) → Per-item Keys
- **TDE key hierarchy:** Device Key (32 bytes, stored locally) → RSA Private Key (AES-CBC + HMAC) → User Key (RSA-OAEP-SHA1)
- **CipherString formats:** Type 0 (AES-CBC no MAC), Type 2 (AES-CBC + HMAC-SHA256), Types 3-6 (RSA-OAEP with SHA1/SHA256)
- **Device key derivation:** HKDF-SHA256 expands the 32-byte device key into separate enc + mac keys for AES-CBC + HMAC encryption
- **MAC verification:** Tries three HMAC variants for compatibility with different server implementations
- **HKDF key stretching:** Used as fallback for user key decryption (expands 32-byte key to separate enc+mac keys)
- **Server compatibility:** Handles quirks of both official Bitwarden and Vaultwarden (e.g., encrypted JSON blobs in the `data` field)

---

## UI (Slint)

### Views

**Login View** — Centered modal with:
- Server URL, email, password fields + "Log in" button (password auth)
- Divider with "Enterprise Single Sign-On" section
- SSO identifier field + "SSO Login" button (opens browser)

**SSO Master Password View** — Shown after successful SSO when the account has a master password:
- Prompt explaining SSO succeeded, master password needed for vault decryption
- Master password field + "Unlock" button

**TDE Approval View** — Shown when SSO succeeds but the device is not yet trusted:
- Explanation that an approval request has been sent to trusted devices and/or the admin console
- Security fingerprint phrase displayed in green (for the approver to verify)
- Status text showing polling progress
- Cancel button to return to login

**Vault View** — Three-column layout:

| Collections Panel (200px) | Items Panel (300px) | Details Panel (flex) |
|---|---|---|
| Hierarchical tree with expand/collapse and collection filtering | Searchable list with selection highlighting | Item title, credential fields, metadata |

### Slint Structs (shared with Rust)

- `CollectionTreeRow` — `{ id, label, depth, has-children, is-expanded }`
- `VaultItemRow` — `{ label }`
- `VaultItemFieldRow` — `{ label, value }`

### Slint Callbacks (vault view)

- `collection-tree-row-clicked(int)` — fired by the `>` expand/collapse arrow; toggles tree expand state only
- `collection-tree-row-selected(int)` — fired by clicking the collection label; sets or clears the active collection filter
- `collection-all-items-clicked()` — fired by the "All Items" row at the top of the tree; clears the collection filter
- `vault-item-clicked(int)`, `search-requested()`, `toggle-password-visibility()` — item panel interactions

### Color Palette (dark theme)

All colors are hardcoded constants in the `.slint` file (e.g., `#0a111d` background, `#e6edf8` primary text, `#223a66` selection accent).

---

## Controller Features (login_controller.rs)

- **Search:** Case-insensitive filtering across item labels and field values. Passwords and TOTP secrets are excluded from search for security.
- **TOTP generation:** Parses `otpauth://` URIs and raw Base32 secrets. Supports SHA1/SHA256/SHA512, configurable digits and period. Auto-refreshes every second via `slint::Timer`. Formats codes as "123 456".
- **Collection tree:** Builds a hierarchical tree from `(uuid, name_path)` pairs. Each `TreeNode` stores the Bitwarden UUIDs of collections whose name path ends at that node. Supports expand/collapse toggling (via arrow click) independently from collection selection (via label click). `collect_uuids_for_path` walks the tree to gather UUIDs for a node and all its descendants, enabling parent-level filtering.
- **Collection filtering:** `active_collection_id: Arc<Mutex<Option<String>>>` holds the name-path of the currently selected tree node. Item visibility is computed by checking whether any of the item's `collection_ids` (Bitwarden UUIDs) intersect the resolved UUID set for the active node. Composes with search: both filters apply simultaneously. An "All Items" entry clears the filter. Clicking an already-selected node deselects it.
- **Password visibility:** Toggle between masked (`********`) and plaintext display.
- **SSO state management:** `SsoPendingState` holds the access token, encrypted user key, KDF config, and HTTP client between SSO token exchange and master password submission.
- **TDE state management:** `TdePendingState` holds the access token, auth request IDs, access code, ephemeral RSA private key, and HTTP client while waiting for device/admin approval. A 10-second `slint::Timer` polls the approval endpoints on a background thread and auto-completes the vault unlock when approved.

---

## Dependencies

| Category | Crates |
|---|---|
| **Crypto** | `aes`, `cbc`, `argon2`, `pbkdf2`, `hmac`, `sha1`, `sha2`, `rsa`, `base64` |
| **HTTP** | `reqwest` (blocking, JSON, rustls-tls) |
| **UI** | `slint`, `slint-build` |
| **Data** | `serde`, `serde_json`, `uuid` |

---

## Key Data Types

### auth/workflow.rs — Public API types

```rust
pub struct LoginResult {
    pub collections: Vec<(String, String)>,  // (collection_uuid, decrypted_name_path)
    pub items: Vec<VaultItemView>,
}

pub struct VaultItemView {
    pub label: String,
    pub fields: Vec<VaultItemFieldView>,
    pub collection_ids: Vec<String>,  // Bitwarden UUIDs this item belongs to
}

pub struct VaultItemFieldView {
    pub label: String,
    pub value: String,
}
```

### auth/vault.rs — Internal decryption types

```rust
pub(super) struct DecryptedVaultView {
    pub(super) collections: Vec<(String, String)>,  // (uuid, decrypted_name_path)
    pub(super) items: Vec<DecryptedVaultItem>,
}

pub(super) struct DecryptedVaultItem {
    pub(super) label: String,
    pub(super) fields: Vec<DecryptedVaultField>,
    pub(super) collection_ids: Vec<String>,
}
```

### auth/sso.rs — SSO types

```rust
pub enum SsoTokenResult {
    NeedsMasterPassword { access_token, protected_user_key, api_base_url, kdf_config, client },
    TrustedDeviceDecrypted(LoginResult),
    NeedsDeviceApproval { pending: TdePendingState, fingerprint: String },
    NoDecryptionPath { message },
}

pub struct KdfConfigSnapshot { kdf, iterations, memory, parallelism }

pub struct TdePendingState {
    access_token, api_base_url, server_url, email, kdf_config, client,
    auth_requests: Vec<(String, bool)>,  // (request_id, needs_bearer_auth)
    access_code: String,
    ephemeral_private_key_der: Vec<u8>,
    device_identifier: String,
}
```

### auth/device_trust.rs — TDE helpers

```rust
struct StoredDeviceKey { device_identifier: String, key: [u8; 32] }
struct EphemeralKeypair { private_key: RsaPrivateKey, public_key_b64: String }

// Storage
fn load_device_key(server_url) -> Option<StoredDeviceKey>
fn save_device_key(server_url, stored) -> Result<(), String>
fn generate_device_key() -> StoredDeviceKey

// Crypto
fn encrypt_with_device_key(device_key, plaintext) -> Result<String>   // type-2 CipherString
fn decrypt_with_device_key(device_key, cipher_string) -> Result<Vec<u8>>
fn encrypt_with_user_key_bytes(user_key_bytes, plaintext) -> Result<String>
fn generate_ephemeral_keypair() -> Result<EphemeralKeypair>
fn rsa_decrypt_user_key(private_key, encrypted_b64) -> Result<Vec<u8>>
fn rsa_encrypt(public_key, plaintext) -> Result<String>
fn fingerprint_phrase(email, public_key_b64) -> String
fn generate_access_code() -> String
```

### auth/models.rs — API models

```rust
struct PreloginResponse { kdf, kdf_iterations, kdf_memory, kdf_parallelism }
struct TokenSuccessResponse { access_token, key, kdf*, user_decryption_options }
struct UserDecryptionOptions { has_master_password, key_connector_option, trusted_device_option }
struct TrustedDeviceOption { encrypted_private_key, encrypted_user_key, has_admin_approval, ... }
struct AuthRequestResponse { id, public_key, fingerprint_phrase }
struct AuthRequestApprovalResponse { id, approved, encrypted_user_key, request_approved }
struct CreateAuthRequest { email, public_key, device_identifier, access_code, type, device_type }
struct TrustDeviceRequest { name, identifier, type, encrypted_user_key, encrypted_public_key, encrypted_private_key }
struct SsoPreValidateResponse { token }
```

### auth/crypto.rs — KDF configuration

```rust
enum KdfConfig {
    Pbkdf2 { iterations: u32 },
    Argon2id { iterations: u32, memory_mib: u32, parallelism: u32 },
}
```

---

## Building & Running

```bash
cargo build          # Compiles Slint UI via build.rs, then builds Rust
cargo run            # Launches the app (tries hardware rendering, falls back to software)
cargo test           # Runs unit tests (TOTP, crypto, field formatting)
```

Requires a Rust toolchain with edition 2024 support.

---

## Known Considerations

- **SSL verification disabled:** `danger_accept_invalid_certs(true)` is set on the HTTP client for self-hosted server compatibility.
- **No persistent storage:** Credentials and vault data are held in memory only; the user must log in every session.
- **Device key stored in plaintext:** `~/.config/bw-native/device_key.json` is not encrypted at rest. The file should be protected by filesystem permissions only.
- **Read-only:** No vault write operations (create/update/delete items) are implemented.
- **Device type hardcoded:** Reports as device type 8 (Linux) regardless of actual platform.
- **No SignalR push:** TDE approval is detected by polling every 10 seconds rather than via the real-time notifications hub. Approval latency is up to 10 seconds.
- **Key Connector not supported:** Orgs using the legacy Key Connector decryption path will get a `NoDecryptionPath` error.

---

## TODO

No open items.
