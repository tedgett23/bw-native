# bw-native — Codebase Summary

A native Bitwarden vault client built in Rust using [Slint](https://slint.dev/) for the UI. It supports logging in to official Bitwarden servers (cloud and EU), Vaultwarden, and generic self-hosted instances. The app syncs and decrypts the full vault client-side (zero-knowledge), then presents it in a three-panel dark-themed desktop UI with collection browsing, item search, and live TOTP code generation.

**Current state:** Read-only. The app can authenticate, sync, and display vault contents but cannot create, edit, or delete items.

---

## Project Structure

```
bw-native/
├── Cargo.toml                  # Dependencies and project metadata (edition 2024)
├── build.rs                    # Compiles Slint UI files at build time
├── src/
│   ├── main.rs                 # Entry point; OpenGL → software renderer fallback
│   ├── auth/                   # Authentication, crypto, and vault logic
│   │   ├── mod.rs              # Exports `try_login` as the single public API
│   │   ├── models.rs           # Serde models for Bitwarden API requests/responses
│   │   ├── errors.rs           # User-friendly error extraction from API responses
│   │   ├── crypto.rs           # KDF key derivation (PBKDF2, Argon2id)
│   │   ├── server.rs           # URL normalization and endpoint resolution
│   │   ├── vault.rs            # Vault sync, multi-layer decryption, data extraction (~976 lines)
│   │   └── workflow.rs         # High-level login orchestration
│   └── ui/                     # Slint ↔ Rust glue
│       ├── mod.rs              # Creates MainWindow and starts event loop
│       └── login_controller.rs # All UI event handlers, TOTP generation, search (~900 lines)
└── ui/
    └── app-window.slint        # Complete UI definition (login + vault views, ~465 lines)
```

**~2,670 lines of code total.**

---

## Architecture

### Layered Design

```
┌─────────────────────────────────────────────┐
│  UI Layer — Slint (ui/app-window.slint)     │  Declarative markup, dark theme, reactive
├─────────────────────────────────────────────┤
│  Controller — login_controller.rs           │  Event handlers, state, threading
├─────────────────────────────────────────────┤
│  Business Logic — auth/workflow.rs          │  Login flow orchestration
├─────────────────────────────────────────────┤
│  Infrastructure — crypto, vault, server     │  HTTP, crypto, decryption, parsing
└─────────────────────────────────────────────┘
```

### Key Patterns

- **Single public entry point:** `auth::try_login(server_url, username, password) -> Result<LoginResult, String>` is the only exported function from the `auth` module. All crypto, HTTP, and vault logic is internal.
- **Threading:** Slint runs on the main thread. Blocking network I/O runs on a background `std::thread`. Cross-thread UI updates use `slint::invoke_from_event_loop`.
- **Shared state:** `Arc<Mutex<T>>` wrappers for collection tree state, vault items, visible indices, and password visibility.
- **Error handling:** `Result<T, String>` throughout with contextual error messages. API errors are parsed to extract user-friendly messages.
- **Renderer fallback:** `main.rs` catches panics/errors from Slint initialization and relaunches the process with `SLINT_BACKEND=winit-software` if hardware rendering fails.

---

## Authentication & Vault Flow

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

### Cryptographic Details (vault.rs)

- **Key hierarchy:** Master Key → User Key (AES-CBC decryption) → Organization Keys (via user key or RSA private key) → Per-item Keys
- **CipherString formats:** Type 0 (AES-CBC no MAC), Type 2 (AES-CBC + HMAC-SHA256), Types 3-6 (RSA-OAEP with SHA1/SHA256)
- **MAC verification:** Tries three HMAC variants for compatibility with different server implementations
- **HKDF key stretching:** Used as fallback for user key decryption (expands 32-byte key to separate enc+mac keys)
- **Server compatibility:** Handles quirks of both official Bitwarden and Vaultwarden (e.g., encrypted JSON blobs in the `data` field)

---

## UI (Slint)

### Views

**Login View** — Centered modal with server URL, email, password fields, status text, and login button.

**Vault View** — Three-column layout:

| Collections Panel (200px) | Items Panel (300px) | Details Panel (flex) |
|---|---|---|
| Hierarchical tree with expand/collapse | Searchable list with selection highlighting | Item title, credential fields, metadata |

### Slint Structs (shared with Rust)

- `CollectionTreeRow` — `{ id, label, depth, has-children, is-expanded }`
- `VaultItemRow` — `{ label }`
- `VaultItemFieldRow` — `{ label, value }`

### Color Palette (dark theme)

All colors are hardcoded constants in the `.slint` file (e.g., `#0a111d` background, `#e6edf8` primary text, `#223a66` selection accent).

---

## Controller Features (login_controller.rs)

- **Search:** Case-insensitive filtering across item labels and field values. Passwords and TOTP secrets are excluded from search for security.
- **TOTP generation:** Parses `otpauth://` URIs and raw Base32 secrets. Supports SHA1/SHA256/SHA512, configurable digits and period. Auto-refreshes every second via `slint::Timer`. Formats codes as "123 456".
- **Collection tree:** Builds a hierarchical tree from flat collection path strings. Supports expand/collapse toggling with visual depth indentation.
- **Password visibility:** Toggle between masked (`********`) and plaintext display.

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
    pub collections: Vec<String>,
    pub items: Vec<VaultItemView>,
}

pub struct VaultItemView {
    pub label: String,
    pub fields: Vec<VaultItemFieldView>,
}

pub struct VaultItemFieldView {
    pub label: String,
    pub value: String,
}
```

### auth/vault.rs — Internal decryption types

```rust
struct SymmetricKey { enc: [u8; 32], mac: Option<[u8; 32]> }  // AES-256 + optional HMAC key
struct CipherString { encryption_type, iv, ciphertext, mac }    // Parsed encrypted field
struct DecryptedVaultView { collections: Vec<String>, items: Vec<DecryptedVaultItem> }
struct DecryptedVaultItem { label: String, fields: Vec<DecryptedVaultField> }
struct DecryptedVaultField { label: String, value: String }
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
- **Read-only:** No vault write operations (create/update/delete items) are implemented.
- **No 2FA support:** Only email/password login; no support for TOTP 2FA, FIDO2, or SSO during authentication.
- **Device type hardcoded:** Reports as device type 8 (Linux) regardless of actual platform.

---

## TODO

### Implement SSO Authentication

Add support for Single Sign-On (SSO) authentication as an alternative to the current email/password flow. This involves:

- **SSO login flow:** Bitwarden SSO uses an OAuth2/OpenID Connect authorization code flow. The client must open a browser (or embedded webview) to the SSO identity provider's login page, receive an authorization code callback, and exchange it for an access token.
- **API endpoints:** The identity server exposes `/accounts/prevalidate-sso` (to check if an org uses SSO given an identifier) and `/connect/token` with `grant_type=authorization_code` (to exchange the SSO code for tokens).
- **Key connector / trusted device flow:** After SSO authentication, the user's encryption keys may come from a Key Connector service or a trusted device flow rather than a master password. The app must handle receiving the user key through these alternate channels.
- **UI changes:** Add an "Enterprise Single Sign-On" option on the login view with an organization identifier input field. The login flow branches: if SSO, open browser for IdP auth; if password, use the existing flow.
- **Files to modify:**
  - `ui/app-window.slint` — Add SSO login UI elements (org identifier field, SSO button, toggle between password/SSO modes)
  - `src/auth/workflow.rs` — Add `try_sso_login()` function implementing the authorization code exchange flow
  - `src/auth/models.rs` — Add SSO-related request/response models (prevalidate, authorization code token request)
  - `src/auth/server.rs` — May need additional endpoint resolution for SSO callback URLs
  - `src/ui/login_controller.rs` — Add handler for SSO login button, manage browser-open and callback

### Make Collections Clickable to Filter Vault Items

Currently, collections are displayed in a tree panel but clicking them only toggles expand/collapse for parent nodes. Selecting a collection should filter the items panel to show only items belonging to that collection (or its children). This involves:

- **Track collection membership:** The vault sync response includes `collectionIds` on each cipher object. During decryption in `vault.rs`, preserve the mapping of each item to its collection IDs. Propagate this data through `DecryptedVaultItem` → `VaultItemView` so the controller has access.
- **Collection selection state:** Add a "selected collection" state to the controller (in addition to the existing expand/collapse state). Clicking a leaf collection selects it; clicking a parent collection could either select it (showing all items in it and its children) or just expand/collapse.
- **Filter logic:** When a collection is selected, filter the visible items list to only those whose `collectionIds` include the selected collection. This interacts with the existing search feature — both filters should compose (search within selected collection).
- **UI feedback:** Highlight the selected collection row in the tree. Add an "All Items" option at the top to clear the filter. Update the items panel title or add a breadcrumb to show which collection is active.
- **Files to modify:**
  - `src/auth/vault.rs` — Include `collection_ids: Vec<String>` in `DecryptedVaultItem` and populate it from cipher data
  - `src/auth/workflow.rs` — Propagate `collection_ids` through `VaultItemView`
  - `src/ui/login_controller.rs` — Add collection selection state, update `on_collection_tree_row_clicked` to set active collection filter, update item filtering to compose with search
  - `ui/app-window.slint` — Add visual selection state for collection rows, possibly an "All Items" entry
