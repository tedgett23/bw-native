use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use reqwest::blocking::Client;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::auth::LoginResult;
use crate::auth::sso::{KdfConfigSnapshot, TdePendingState};

/// Holds the SSO token exchange result while waiting for the user to enter
/// their master password to decrypt the vault.
struct SsoPendingState {
    access_token: String,
    protected_user_key: String,
    api_base_url: String,
    kdf_config: KdfConfigSnapshot,
    client: Client,
    email: String,
}

#[derive(Clone, Default)]
struct VaultItemUiState {
    label: String,
    fields: Vec<(String, String)>,
    collection_ids: Vec<String>,
}

fn model_from_item_rows(
    items: &[VaultItemUiState],
    visible_indices: &[usize],
) -> ModelRc<crate::VaultItemRow> {
    let rows: Vec<crate::VaultItemRow> = visible_indices
        .iter()
        .filter_map(|index| items.get(*index))
        .map(|item| crate::VaultItemRow {
            label: SharedString::from(&item.label),
        })
        .collect();
    ModelRc::new(VecModel::from(rows))
}

fn model_from_item_fields(fields: &[(String, String)]) -> ModelRc<crate::VaultItemFieldRow> {
    let rows: Vec<crate::VaultItemFieldRow> = fields
        .iter()
        .map(|(label, value)| crate::VaultItemFieldRow {
            label: SharedString::from(label),
            value: SharedString::from(value),
        })
        .collect();
    ModelRc::new(VecModel::from(rows))
}

fn is_password_label(label: &str) -> bool {
    label
        .split('/')
        .next_back()
        .map(|tail| tail.trim().eq_ignore_ascii_case("password"))
        .unwrap_or(false)
}

fn is_totp_label(label: &str) -> bool {
    label
        .split('/')
        .next_back()
        .map(|tail| {
            let tail = tail.trim();
            tail.eq_ignore_ascii_case("totp") || tail.eq_ignore_ascii_case("verification code")
        })
        .unwrap_or(false)
}

fn has_password_field(fields: &[(String, String)]) -> bool {
    fields.iter().any(|(label, _)| is_password_label(label))
}

fn build_visible_item_indices(
    items: &[VaultItemUiState],
    raw_query: &str,
    active_uuids: Option<&HashSet<String>>,
) -> Vec<usize> {
    let query = raw_query.trim().to_lowercase();
    items
        .iter()
        .enumerate()
        .filter_map(|(index, item)| {
            if let Some(uuids) = active_uuids {
                if !item.collection_ids.iter().any(|id| uuids.contains(id)) {
                    return None;
                }
            }
            item_matches_query(item, &query).then_some(index)
        })
        .collect()
}

fn item_matches_query(item: &VaultItemUiState, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }

    if item.label.to_lowercase().contains(query) {
        return true;
    }

    item.fields.iter().any(|(label, value)| {
        if is_password_label(label) || is_totp_label(label) {
            return false;
        }

        label.to_lowercase().contains(query) || value.to_lowercase().contains(query)
    })
}

fn to_totp_code(raw_value: &str) -> Option<String> {
    let config = parse_totp_config(raw_value)?;
    let unix_now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    generate_totp_code(
        &config.secret,
        config.digits,
        config.period,
        unix_now,
        &config.algorithm,
    )
}

struct TotpConfig {
    secret: Vec<u8>,
    digits: u32,
    period: u64,
    algorithm: String,
}

fn parse_totp_config(raw_value: &str) -> Option<TotpConfig> {
    let trimmed = raw_value.trim();
    if trimmed.is_empty() {
        return None;
    }

    if trimmed.starts_with("otpauth://") {
        parse_otpauth_uri(trimmed)
    } else {
        let secret = decode_base32_secret(trimmed)?;
        Some(TotpConfig {
            secret,
            digits: 6,
            period: 30,
            algorithm: "SHA1".to_string(),
        })
    }
}

fn parse_otpauth_uri(uri: &str) -> Option<TotpConfig> {
    let (_, query) = uri.split_once('?')?;
    let mut secret = None::<Vec<u8>>;
    let mut digits = 6_u32;
    let mut period = 30_u64;
    let mut algorithm = "SHA1".to_string();

    for pair in query.split('&') {
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = raw_key.trim().to_lowercase();
        let value = percent_decode(raw_value.trim());

        match key.as_str() {
            "secret" => {
                secret = decode_base32_secret(&value);
            }
            "digits" => {
                if let Ok(parsed) = value.parse::<u32>() {
                    if (6..=10).contains(&parsed) {
                        digits = parsed;
                    }
                }
            }
            "period" => {
                if let Ok(parsed) = value.parse::<u64>() {
                    if parsed > 0 {
                        period = parsed;
                    }
                }
            }
            "algorithm" => {
                let normalized = value.to_uppercase();
                if normalized == "SHA1" || normalized == "SHA256" || normalized == "SHA512" {
                    algorithm = normalized;
                }
            }
            _ => {}
        }
    }

    Some(TotpConfig {
        secret: secret?,
        digits,
        period,
        algorithm,
    })
}

fn decode_base32_secret(secret: &str) -> Option<Vec<u8>> {
    let mut bits: u32 = 0;
    let mut bit_count: u8 = 0;
    let mut output = Vec::new();

    for ch in secret.chars() {
        if ch == '=' || ch.is_whitespace() || ch == '-' {
            continue;
        }

        let value = match ch.to_ascii_uppercase() {
            'A'..='Z' => (ch.to_ascii_uppercase() as u8 - b'A') as u8,
            '2'..='7' => (ch as u8 - b'2') + 26,
            _ => return None,
        };

        bits = (bits << 5) | value as u32;
        bit_count += 5;

        while bit_count >= 8 {
            bit_count -= 8;
            output.push(((bits >> bit_count) & 0xFF) as u8);
        }
    }

    if output.is_empty() {
        None
    } else {
        Some(output)
    }
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

fn generate_totp_code(
    secret: &[u8],
    digits: u32,
    period: u64,
    unix_time_secs: u64,
    algorithm: &str,
) -> Option<String> {
    if secret.is_empty() || period == 0 {
        return None;
    }

    let counter = unix_time_secs / period;
    let counter_bytes = counter.to_be_bytes();
    let hmac = hmac_digest(algorithm, secret, &counter_bytes)?;

    let offset = (hmac.last()? & 0x0F) as usize;
    if offset + 4 > hmac.len() {
        return None;
    }

    let binary = ((hmac[offset] as u32 & 0x7F) << 24)
        | ((hmac[offset + 1] as u32) << 16)
        | ((hmac[offset + 2] as u32) << 8)
        | (hmac[offset + 3] as u32);
    let modulus = 10_u32.checked_pow(digits).unwrap_or(1_000_000);
    let otp = binary % modulus;
    let code = format!("{otp:0width$}", width = digits as usize);
    Some(format_totp_code(&code))
}

fn hmac_digest(algorithm: &str, key: &[u8], message: &[u8]) -> Option<Vec<u8>> {
    match algorithm {
        "SHA256" => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
            mac.update(message);
            Some(mac.finalize().into_bytes().to_vec())
        }
        "SHA512" => {
            let mut mac = Hmac::<Sha512>::new_from_slice(key).ok()?;
            mac.update(message);
            Some(mac.finalize().into_bytes().to_vec())
        }
        _ => {
            let mut mac = Hmac::<Sha1>::new_from_slice(key).ok()?;
            mac.update(message);
            Some(mac.finalize().into_bytes().to_vec())
        }
    }
}

fn format_totp_code(code: &str) -> String {
    if code.len() == 6 {
        format!("{} {}", &code[..3], &code[3..])
    } else {
        code.to_string()
    }
}

fn display_fields(fields: &[(String, String)], is_password_visible: bool) -> Vec<(String, String)> {
    fields
        .iter()
        .map(|(label, value)| {
            if is_password_label(label) && !is_password_visible {
                (label.clone(), "********".to_string())
            } else if is_totp_label(label) {
                match to_totp_code(value) {
                    Some(code) => (label.clone(), code),
                    None => (label.clone(), value.clone()),
                }
            } else {
                (label.clone(), value.clone())
            }
        })
        .collect()
}

fn apply_selected_item(
    window: &crate::MainWindow,
    row_index: usize,
    item: &VaultItemUiState,
    is_password_visible: bool,
) {
    let Ok(index) = i32::try_from(row_index) else {
        return;
    };

    window.set_selected_vault_item_index(index);
    window.set_selected_vault_item_title(item.label.clone().into());
    window.set_selected_has_password(has_password_field(&item.fields));
    window.set_is_password_visible(is_password_visible);

    let fields_to_display = display_fields(&item.fields, is_password_visible);
    window.set_selected_vault_item_fields(model_from_item_fields(&fields_to_display));
    window.set_selected_vault_item_empty_text(
        if item.fields.is_empty() {
            "No non-empty fields were found in this item's data payload."
        } else {
            ""
        }
        .into(),
    );
}

#[derive(Default)]
struct TreeNode {
    /// UUIDs of collections whose name path ends exactly at this node.
    uuids: HashSet<String>,
    children: BTreeMap<String, TreeNode>,
}

struct CollectionTreeState {
    root: TreeNode,
    expanded_nodes: HashSet<String>,
    visible_rows: Vec<crate::CollectionTreeRow>,
}

impl CollectionTreeState {
    fn from_collections(collections: &[(String, String)]) -> Self {
        let mut root = TreeNode::default();

        for (uuid, name_path) in collections {
            let mut node = &mut root;
            for part in name_path.split('/').filter(|part| !part.is_empty()) {
                node = node.children.entry(part.to_string()).or_default();
            }
            node.uuids.insert(uuid.clone());
        }

        let mut expanded_nodes = HashSet::new();
        collect_expandable_node_ids(&root, "", &mut expanded_nodes);

        let mut state = Self {
            root,
            expanded_nodes,
            visible_rows: Vec::new(),
        };
        state.rebuild_rows();
        state
    }

    fn toggle_row(&mut self, row_index: usize) {
        let Some(row) = self.visible_rows.get(row_index) else {
            return;
        };

        if !row.has_children {
            return;
        }

        let node_id = row.id.to_string();
        if self.expanded_nodes.contains(&node_id) {
            self.expanded_nodes.remove(&node_id);
        } else {
            self.expanded_nodes.insert(node_id);
        }

        self.rebuild_rows();
    }

    /// Collect all UUIDs reachable at or below the node identified by `name_path`.
    fn collect_uuids_for_path(&self, name_path: &str) -> HashSet<String> {
        let mut node = &self.root;
        for part in name_path.split('/').filter(|p| !p.is_empty()) {
            match node.children.get(part) {
                Some(child) => node = child,
                None => return HashSet::new(),
            }
        }
        let mut uuids = HashSet::new();
        collect_node_uuids(node, &mut uuids);
        uuids
    }

    fn to_model(&self) -> ModelRc<crate::CollectionTreeRow> {
        ModelRc::new(VecModel::from(self.visible_rows.clone()))
    }

    fn rebuild_rows(&mut self) {
        let mut rows = Vec::new();
        flatten_tree(&self.root, "", 0, &self.expanded_nodes, &mut rows);
        self.visible_rows = rows;
    }
}

/// Recursively collect all UUIDs in a subtree.
fn collect_node_uuids(node: &TreeNode, out: &mut HashSet<String>) {
    for uuid in &node.uuids {
        out.insert(uuid.clone());
    }
    for child in node.children.values() {
        collect_node_uuids(child, out);
    }
}

fn collect_expandable_node_ids(node: &TreeNode, prefix: &str, expanded: &mut HashSet<String>) {
    for (name, child) in &node.children {
        let id = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };

        if !child.children.is_empty() {
            expanded.insert(id.clone());
            collect_expandable_node_ids(child, &id, expanded);
        }
    }
}

fn flatten_tree(
    node: &TreeNode,
    prefix: &str,
    depth: i32,
    expanded: &HashSet<String>,
    rows: &mut Vec<crate::CollectionTreeRow>,
) {
    for (name, child) in &node.children {
        let id = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };

        let has_children = !child.children.is_empty();
        let is_expanded = has_children && expanded.contains(&id);

        rows.push(crate::CollectionTreeRow {
            id: id.clone().into(),
            label: name.clone().into(),
            depth,
            has_children,
            is_expanded,
        });

        if has_children && is_expanded {
            flatten_tree(child, &id, depth + 1, expanded, rows);
        }
    }
}

pub(super) fn attach_handlers(window: &crate::MainWindow) {
    let weak_window = window.as_weak();
    let tree_state = Arc::new(Mutex::new(None::<CollectionTreeState>));
    let vault_item_state = Arc::new(Mutex::new(Vec::<VaultItemUiState>::new()));
    let visible_item_indices_state = Arc::new(Mutex::new(Vec::<usize>::new()));
    let password_visible_state = Arc::new(Mutex::new(false));
    // None means "All Items"; Some(id) means filter to that collection's items.
    let active_collection_id: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    {
        let weak_window = weak_window.clone();
        let tree_state = tree_state.clone();
        let vault_item_state = vault_item_state.clone();
        let visible_item_indices_state = visible_item_indices_state.clone();
        let password_visible_state = password_visible_state.clone();
        let active_collection_id = active_collection_id.clone();

        window.on_collection_tree_row_clicked(move |row_index| {
            let Some(window) = weak_window.upgrade() else {
                return;
            };

            let Ok(row_index) = usize::try_from(row_index) else {
                return;
            };

            let Ok(mut state_ref) = tree_state.lock() else {
                return;
            };
            let Some(state) = state_ref.as_mut() else {
                return;
            };

            // For parent nodes: toggle expand/collapse.
            // For leaf nodes: select the collection as the active filter.
            let row = state.visible_rows.get(row_index).cloned();
            let Some(row) = row else { return };

            if row.has_children {
                // Parent node: toggle expand/collapse.
                state.toggle_row(row_index);
                window.set_collection_tree_rows(state.to_model());
            }

            {
                // Any node (parent or leaf): toggle as active collection filter.
                let node_path = row.id.to_string();

                // Toggle: clicking the already-selected node deselects it.
                let new_active = {
                    let Ok(mut active_ref) = active_collection_id.lock() else {
                        return;
                    };
                    if active_ref.as_deref() == Some(&node_path) {
                        *active_ref = None;
                        None
                    } else {
                        *active_ref = Some(node_path.clone());
                        Some(node_path)
                    }
                };

                window.set_active_collection_id(new_active.as_deref().unwrap_or("").into());

                // Resolve UUIDs for the selected node and all its descendants.
                let active_uuids = new_active
                    .as_deref()
                    .map(|path| state.collect_uuids_for_path(path));

                // Refilter items using both search query and new collection filter.
                let search_query = window.get_search_query().to_string();
                let Ok(items_ref) = vault_item_state.lock() else {
                    return;
                };
                let next_indices =
                    build_visible_item_indices(&items_ref, &search_query, active_uuids.as_ref());
                window.set_vault_item_rows(model_from_item_rows(&items_ref, &next_indices));

                if let Ok(mut visible_ref) = visible_item_indices_state.lock() {
                    *visible_ref = next_indices.clone();
                }

                if let Ok(mut pw) = password_visible_state.lock() {
                    *pw = false;
                }
                window.set_is_password_visible(false);

                if next_indices.is_empty() {
                    window.set_selected_vault_item_index(-1);
                    window.set_selected_vault_item_title("".into());
                    window.set_selected_vault_item_fields(ModelRc::new(VecModel::<
                        crate::VaultItemFieldRow,
                    >::default(
                    )));
                    window.set_selected_vault_item_empty_text(
                        "No vault items in this collection.".into(),
                    );
                    window.set_selected_has_password(false);
                } else if let Some(item) = items_ref.get(next_indices[0]) {
                    apply_selected_item(&window, 0, item, false);
                }
            }
        });
    }

    {
        let weak_window = weak_window.clone();
        let vault_item_state = vault_item_state.clone();
        let visible_item_indices_state = visible_item_indices_state.clone();
        let password_visible_state = password_visible_state.clone();
        let active_collection_id = active_collection_id.clone();

        window.on_collection_all_items_clicked(move || {
            let Some(window) = weak_window.upgrade() else {
                return;
            };

            // Clear the collection filter
            if let Ok(mut active_ref) = active_collection_id.lock() {
                *active_ref = None;
            }
            window.set_active_collection_id("".into());

            // Rebuild visible items with no collection filter
            let search_query = window.get_search_query().to_string();
            let Ok(items_ref) = vault_item_state.lock() else {
                return;
            };
            let next_indices = build_visible_item_indices(&items_ref, &search_query, None);
            window.set_vault_item_rows(model_from_item_rows(&items_ref, &next_indices));

            if let Ok(mut visible_ref) = visible_item_indices_state.lock() {
                *visible_ref = next_indices.clone();
            }

            if let Ok(mut pw) = password_visible_state.lock() {
                *pw = false;
            }
            window.set_is_password_visible(false);

            if next_indices.is_empty() {
                window.set_selected_vault_item_index(-1);
                window.set_selected_vault_item_title("".into());
                window.set_selected_vault_item_fields(ModelRc::new(VecModel::<
                    crate::VaultItemFieldRow,
                >::default()));
                window.set_selected_vault_item_empty_text("No vault items loaded.".into());
                window.set_selected_has_password(false);
            } else if let Some(item) = items_ref.get(next_indices[0]) {
                apply_selected_item(&window, 0, item, false);
            }
        });
    }

    {
        let weak_window = weak_window.clone();
        let vault_item_state = vault_item_state.clone();
        let visible_item_indices_state = visible_item_indices_state.clone();
        let password_visible_state = password_visible_state.clone();

        window.on_vault_item_clicked(move |row_index| {
            let Some(window) = weak_window.upgrade() else {
                return;
            };

            let Ok(row_index) = usize::try_from(row_index) else {
                return;
            };

            let source_index = {
                let Ok(visible_indices_ref) = visible_item_indices_state.lock() else {
                    return;
                };
                let Some(source_index) = visible_indices_ref.get(row_index).copied() else {
                    return;
                };
                source_index
            };

            let Ok(items_ref) = vault_item_state.lock() else {
                return;
            };
            let Some(item) = items_ref.get(source_index) else {
                return;
            };

            if let Ok(mut visible_state) = password_visible_state.lock() {
                *visible_state = false;
            } else {
                return;
            }

            apply_selected_item(&window, row_index, item, false);
        });
    }

    {
        let weak_window = weak_window.clone();
        let vault_item_state = vault_item_state.clone();
        let visible_item_indices_state = visible_item_indices_state.clone();
        let password_visible_state = password_visible_state.clone();

        window.on_toggle_password_visibility(move || {
            let Some(window) = weak_window.upgrade() else {
                return;
            };

            let selected_index = window.get_selected_vault_item_index();
            let Ok(selected_index) = usize::try_from(selected_index) else {
                return;
            };

            let source_index = {
                let Ok(visible_indices_ref) = visible_item_indices_state.lock() else {
                    return;
                };
                let Some(source_index) = visible_indices_ref.get(selected_index).copied() else {
                    return;
                };
                source_index
            };

            let Ok(items_ref) = vault_item_state.lock() else {
                return;
            };
            let Some(item) = items_ref.get(source_index) else {
                return;
            };

            if !has_password_field(&item.fields) {
                return;
            }

            let Ok(mut visible_state) = password_visible_state.lock() else {
                return;
            };
            *visible_state = !*visible_state;
            apply_selected_item(&window, selected_index, item, *visible_state);
        });
    }

    {
        let weak_window = weak_window.clone();
        let tree_state = tree_state.clone();
        let vault_item_state = vault_item_state.clone();
        let visible_item_indices_state = visible_item_indices_state.clone();
        let password_visible_state = password_visible_state.clone();
        let active_collection_id = active_collection_id.clone();

        window.on_search_requested(move || {
            let Some(window) = weak_window.upgrade() else {
                return;
            };

            let search_query = window.get_search_query().to_string();
            let has_active_search = !search_query.trim().is_empty();
            window.set_has_active_search(has_active_search);

            let selected_source_index = {
                let selected_visible_index =
                    usize::try_from(window.get_selected_vault_item_index()).ok();
                let Ok(visible_indices_ref) = visible_item_indices_state.lock() else {
                    return;
                };

                selected_visible_index.and_then(|index| visible_indices_ref.get(index).copied())
            };

            let Ok(items_ref) = vault_item_state.lock() else {
                return;
            };

            let active_col_path = active_collection_id.lock().ok().and_then(|g| g.clone());
            let active_uuids = active_col_path.as_deref().and_then(|path| {
                tree_state
                    .lock()
                    .ok()
                    .and_then(|g| g.as_ref().map(|s| s.collect_uuids_for_path(path)))
            });
            let next_visible_indices =
                build_visible_item_indices(&items_ref, &search_query, active_uuids.as_ref());
            window.set_vault_item_rows(model_from_item_rows(&items_ref, &next_visible_indices));

            if let Ok(mut visible_indices_ref) = visible_item_indices_state.lock() {
                *visible_indices_ref = next_visible_indices.clone();
            } else {
                return;
            }

            if let Ok(mut visible_state) = password_visible_state.lock() {
                *visible_state = false;
            }
            window.set_is_password_visible(false);

            if next_visible_indices.is_empty() {
                window.set_selected_vault_item_index(-1);
                window.set_selected_vault_item_title("".into());
                window.set_selected_vault_item_fields(ModelRc::new(VecModel::<
                    crate::VaultItemFieldRow,
                >::default()));
                window.set_selected_vault_item_empty_text(
                    if has_active_search {
                        "No vault items match your search."
                    } else {
                        "No vault items loaded."
                    }
                    .into(),
                );
                window.set_selected_has_password(false);
                return;
            }

            let selected_visible_index = selected_source_index
                .and_then(|source_index| {
                    next_visible_indices
                        .iter()
                        .position(|visible_source_index| *visible_source_index == source_index)
                })
                .unwrap_or(0);

            let source_index = next_visible_indices[selected_visible_index];
            if let Some(item) = items_ref.get(source_index) {
                apply_selected_item(&window, selected_visible_index, item, false);
            }
        });
    }

    let weak_window_for_login = weak_window.clone();
    let tree_state_for_login = tree_state.clone();
    let vault_item_state_for_login = vault_item_state.clone();
    let visible_item_indices_for_login = visible_item_indices_state.clone();
    let password_visible_state_for_login = password_visible_state.clone();
    let active_collection_id_for_login = active_collection_id.clone();
    window.on_login_requested(move || {
        let Some(window) = weak_window_for_login.upgrade() else {
            return;
        };

        if window.get_is_logging_in() {
            return;
        }

        let server_url = window.get_server_url().to_string();
        let username = window.get_username().to_string();
        let password = window.get_password().to_string();

        window.set_status_is_error(false);
        window.set_status_text("Logging in...".into());
        window.set_is_logging_in(true);
        window.set_is_vault_view(false);
        window.set_search_query("".into());
        window.set_has_active_search(false);
        window.set_collection_tree_rows(ModelRc::new(
            VecModel::<crate::CollectionTreeRow>::default(),
        ));
        window.set_vault_item_rows(ModelRc::new(VecModel::<crate::VaultItemRow>::default()));
        window.set_selected_vault_item_fields(ModelRc::new(
            VecModel::<crate::VaultItemFieldRow>::default(),
        ));
        window.set_selected_vault_item_index(-1);
        window.set_selected_vault_item_title("".into());
        window.set_selected_vault_item_empty_text("Select an item to view details.".into());
        window.set_selected_has_password(false);
        window.set_is_password_visible(false);
        window.set_active_collection_id("".into());
        if let Ok(mut state) = tree_state_for_login.lock() {
            *state = None;
        }
        if let Ok(mut items) = vault_item_state_for_login.lock() {
            items.clear();
        }
        if let Ok(mut visible_indices) = visible_item_indices_for_login.lock() {
            visible_indices.clear();
        }
        if let Ok(mut visible_state) = password_visible_state_for_login.lock() {
            *visible_state = false;
        }
        if let Ok(mut active_col) = active_collection_id_for_login.lock() {
            *active_col = None;
        }

        let weak_for_thread = weak_window_for_login.clone();
        let tree_state = tree_state_for_login.clone();
        let vault_item_state = vault_item_state_for_login.clone();
        let visible_item_indices = visible_item_indices_for_login.clone();
        let password_visible_state = password_visible_state_for_login.clone();
        thread::spawn(move || {
            let result = crate::auth::try_login(&server_url, &username, &password);

            let _ = slint::invoke_from_event_loop(move || {
                if let Some(window) = weak_for_thread.upgrade() {
                    window.set_is_logging_in(false);
                    match result {
                        Ok(result) => {
                            window.set_status_is_error(false);
                            window.set_status_text(
                                format!(
                                    "Login successful. Loaded {} collections and {} items.",
                                    result.collections.len(),
                                    result.items.len()
                                )
                                .into(),
                            );
                            window.set_password("".into());
                            let collection_state =
                                CollectionTreeState::from_collections(&result.collections);
                            window.set_collection_tree_rows(collection_state.to_model());
                            let item_rows: Vec<VaultItemUiState> = result
                                .items
                                .into_iter()
                                .map(|item| VaultItemUiState {
                                    label: item.label,
                                    fields: item
                                        .fields
                                        .into_iter()
                                        .map(|field| (field.label, field.value))
                                        .collect(),
                                    collection_ids: item.collection_ids,
                                })
                                .collect();
                            let visible_indices: Vec<usize> = (0..item_rows.len()).collect();
                            window.set_vault_item_rows(model_from_item_rows(
                                &item_rows,
                                &visible_indices,
                            ));
                            if item_rows.is_empty() {
                                window.set_selected_vault_item_index(-1);
                                window.set_selected_vault_item_title("".into());
                                window.set_selected_vault_item_fields(ModelRc::new(VecModel::<
                                    crate::VaultItemFieldRow,
                                >::default(
                                )));
                                window.set_selected_vault_item_empty_text(
                                    "No vault items loaded.".into(),
                                );
                                window.set_selected_has_password(false);
                                window.set_is_password_visible(false);
                            } else {
                                if let Ok(mut visible_state) = password_visible_state.lock() {
                                    *visible_state = false;
                                    apply_selected_item(&window, 0, &item_rows[0], *visible_state);
                                } else {
                                    apply_selected_item(&window, 0, &item_rows[0], false);
                                }
                            }
                            if let Ok(mut state) = tree_state.lock() {
                                *state = Some(collection_state);
                            }
                            if let Ok(mut items) = vault_item_state.lock() {
                                *items = item_rows;
                            }
                            if let Ok(mut visible_ref) = visible_item_indices.lock() {
                                *visible_ref = visible_indices;
                            }
                            window.set_is_vault_view(true);
                        }
                        Err(error) => {
                            window.set_status_is_error(true);
                            window.set_status_text(error.into());
                        }
                    }
                }
            });
        });
    });

    let sso_pending_state: Arc<Mutex<Option<SsoPendingState>>> = Arc::new(Mutex::new(None));
    let tde_pending_state: Arc<Mutex<Option<TdePendingState>>> = Arc::new(Mutex::new(None));

    {
        let weak_window = weak_window.clone();
        let sso_pending_state = sso_pending_state.clone();
        let tde_pending_state = tde_pending_state.clone();
        let tree_state = tree_state.clone();
        let vault_item_state = vault_item_state.clone();
        let visible_item_indices_state = visible_item_indices_state.clone();
        let password_visible_state = password_visible_state.clone();
        let active_collection_id = active_collection_id.clone();

        window.on_sso_login_requested(move || {
            let Some(window) = weak_window.upgrade() else {
                return;
            };

            if window.get_is_logging_in() {
                return;
            }

            let server_url = window.get_server_url().to_string();
            let org_identifier = window.get_sso_identifier().to_string();
            let email = window.get_username().to_string();

            window.set_status_is_error(false);
            window.set_status_text("Opening browser for SSO login...".into());
            window.set_is_logging_in(true);

            let weak_for_thread = weak_window.clone();
            let sso_pending = sso_pending_state.clone();
            let tde_pending = tde_pending_state.clone();
            let tree_state = tree_state.clone();
            let vault_item_state = vault_item_state.clone();
            let visible_item_indices = visible_item_indices_state.clone();
            let password_visible_state = password_visible_state.clone();
            let active_collection_id = active_collection_id.clone();
            thread::spawn(move || {
                let result = crate::auth::try_sso_login(&server_url, &org_identifier, &email);

                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(window) = weak_for_thread.upgrade() {
                        window.set_is_logging_in(false);
                        match result {
                            Ok(crate::auth::SsoTokenResult::NeedsMasterPassword {
                                access_token,
                                protected_user_key,
                                api_base_url,
                                kdf_config,
                                client,
                            }) => {
                                if let Ok(mut pending) = sso_pending.lock() {
                                    *pending = Some(SsoPendingState {
                                        access_token,
                                        protected_user_key,
                                        api_base_url,
                                        kdf_config,
                                        client,
                                        email: email.clone(),
                                    });
                                }
                                window.set_status_is_error(false);
                                window.set_status_text("".into());
                                window.set_is_sso_awaiting_password(true);
                                window.set_sso_master_password("".into());
                            }
                            Ok(crate::auth::SsoTokenResult::TrustedDeviceDecrypted(result)) => {
                                // Device was already trusted — vault decrypted immediately.
                                populate_vault_after_login(
                                    &window,
                                    result,
                                    "SSO login successful (trusted device). Loaded {} collections and {} items.",
                                    &tree_state,
                                    &vault_item_state,
                                    &visible_item_indices,
                                    &password_visible_state,
                                    &active_collection_id,
                                );
                            }
                            Ok(crate::auth::SsoTokenResult::NeedsDeviceApproval {
                                pending,
                                fingerprint,
                            }) => {
                                if let Ok(mut tde) = tde_pending.lock() {
                                    *tde = Some(pending);
                                }
                                window.set_status_is_error(false);
                                window.set_status_text(
                                    "Waiting for approval… check your other devices or the admin console.".into(),
                                );
                                window.set_tde_fingerprint(fingerprint.into());
                                window.set_is_tde_awaiting_approval(true);
                            }
                            Ok(crate::auth::SsoTokenResult::NoDecryptionPath { message }) => {
                                window.set_status_is_error(true);
                                window.set_status_text(message.into());
                            }
                            Err(error) => {
                                window.set_status_is_error(true);
                                window.set_status_text(error.into());
                            }
                        }
                    }
                });
            });
        });
    }

    // ── TDE cancel ────────────────────────────────────────────────────────────
    {
        let weak_window = weak_window.clone();
        let tde_pending_state = tde_pending_state.clone();

        window.on_tde_approval_cancel_requested(move || {
            let Some(window) = weak_window.upgrade() else {
                return;
            };
            if let Ok(mut tde) = tde_pending_state.lock() {
                *tde = None;
            }
            window.set_is_tde_awaiting_approval(false);
            window.set_tde_fingerprint("".into());
            window.set_status_text("".into());
            window.set_status_is_error(false);
        });
    }

    {
        let weak_window = weak_window.clone();
        let sso_pending_state = sso_pending_state.clone();
        let tree_state = tree_state.clone();
        let vault_item_state = vault_item_state.clone();
        let visible_item_indices_state = visible_item_indices_state.clone();
        let password_visible_state = password_visible_state.clone();
        let active_collection_id = active_collection_id.clone();

        window.on_sso_master_password_submitted(move || {
            let Some(window) = weak_window.upgrade() else {
                return;
            };

            if window.get_is_logging_in() {
                return;
            }

            let master_password = window.get_sso_master_password().to_string();
            if master_password.trim().is_empty() {
                window.set_status_is_error(true);
                window.set_status_text("Master password is required.".into());
                return;
            }

            let pending = {
                let Ok(mut pending_ref) = sso_pending_state.lock() else {
                    return;
                };
                pending_ref.take()
            };

            let Some(pending) = pending else {
                window.set_status_is_error(true);
                window.set_status_text("SSO session expired. Please try again.".into());
                window.set_is_sso_awaiting_password(false);
                return;
            };

            window.set_status_is_error(false);
            window.set_status_text("Decrypting vault...".into());
            window.set_is_logging_in(true);
            window.set_search_query("".into());
            window.set_has_active_search(false);

            let weak_for_thread = weak_window.clone();
            let tree_state = tree_state.clone();
            let vault_item_state = vault_item_state.clone();
            let visible_item_indices = visible_item_indices_state.clone();
            let password_visible_state = password_visible_state.clone();
            let active_collection_id = active_collection_id.clone();
            thread::spawn(move || {
                let result = crate::auth::complete_sso_with_master_password(
                    &pending.client,
                    &pending.api_base_url,
                    &pending.access_token,
                    &pending.protected_user_key,
                    &master_password,
                    &pending.email,
                    &pending.kdf_config,
                );

                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(window) = weak_for_thread.upgrade() {
                        window.set_is_logging_in(false);
                        match result {
                            Ok(result) => {
                                window.set_status_is_error(false);
                                window.set_status_text(
                                    format!(
                                        "SSO login successful. Loaded {} collections and {} items.",
                                        result.collections.len(),
                                        result.items.len()
                                    )
                                    .into(),
                                );
                                window.set_sso_master_password("".into());
                                window.set_is_sso_awaiting_password(false);
                                window.set_active_collection_id("".into());
                                if let Ok(mut active_col) = active_collection_id.lock() {
                                    *active_col = None;
                                }

                                let collection_state =
                                    CollectionTreeState::from_collections(&result.collections);
                                window.set_collection_tree_rows(collection_state.to_model());

                                let item_rows: Vec<VaultItemUiState> = result
                                    .items
                                    .into_iter()
                                    .map(|item| VaultItemUiState {
                                        label: item.label,
                                        fields: item
                                            .fields
                                            .into_iter()
                                            .map(|field| (field.label, field.value))
                                            .collect(),
                                        collection_ids: item.collection_ids,
                                    })
                                    .collect();

                                let visible_indices: Vec<usize> = (0..item_rows.len()).collect();
                                window.set_vault_item_rows(model_from_item_rows(
                                    &item_rows,
                                    &visible_indices,
                                ));

                                if item_rows.is_empty() {
                                    window.set_selected_vault_item_index(-1);
                                    window.set_selected_vault_item_title("".into());
                                    window.set_selected_vault_item_fields(ModelRc::new(
                                        VecModel::<crate::VaultItemFieldRow>::default(),
                                    ));
                                    window.set_selected_vault_item_empty_text(
                                        "No vault items loaded.".into(),
                                    );
                                    window.set_selected_has_password(false);
                                    window.set_is_password_visible(false);
                                } else {
                                    if let Ok(mut visible_state) = password_visible_state.lock() {
                                        *visible_state = false;
                                        apply_selected_item(
                                            &window,
                                            0,
                                            &item_rows[0],
                                            *visible_state,
                                        );
                                    } else {
                                        apply_selected_item(&window, 0, &item_rows[0], false);
                                    }
                                }

                                if let Ok(mut state) = tree_state.lock() {
                                    *state = Some(collection_state);
                                }
                                if let Ok(mut items) = vault_item_state.lock() {
                                    *items = item_rows;
                                }
                                if let Ok(mut visible_ref) = visible_item_indices.lock() {
                                    *visible_ref = visible_indices;
                                }
                                window.set_is_vault_view(true);
                            }
                            Err(error) => {
                                // Put the pending state back so the user can retry
                                // (we already consumed it with take())
                                window.set_status_is_error(true);
                                window.set_status_text(error.into());
                            }
                        }
                    }
                });
            });
        });
    }

    schedule_totp_refresh(
        weak_window.clone(),
        vault_item_state.clone(),
        visible_item_indices_state.clone(),
        password_visible_state.clone(),
    );

    schedule_tde_approval_poll(
        weak_window.clone(),
        tde_pending_state.clone(),
        tree_state.clone(),
        vault_item_state.clone(),
        visible_item_indices_state.clone(),
        password_visible_state.clone(),
        active_collection_id.clone(),
    );
}

/// Populate the vault UI after a successful login (any path).
/// `status_template` must contain two `{}` placeholders for collection and item counts.
fn populate_vault_after_login(
    window: &crate::MainWindow,
    result: LoginResult,
    status_template: &str,
    tree_state: &Arc<Mutex<Option<CollectionTreeState>>>,
    vault_item_state: &Arc<Mutex<Vec<VaultItemUiState>>>,
    visible_item_indices: &Arc<Mutex<Vec<usize>>>,
    password_visible_state: &Arc<Mutex<bool>>,
    active_collection_id: &Arc<Mutex<Option<String>>>,
) {
    window.set_status_is_error(false);
    window.set_status_text(
        status_template
            .replacen("{}", &result.collections.len().to_string(), 1)
            .replacen("{}", &result.items.len().to_string(), 1)
            .into(),
    );
    window.set_sso_master_password("".into());
    window.set_is_sso_awaiting_password(false);
    window.set_is_tde_awaiting_approval(false);
    window.set_tde_fingerprint("".into());
    window.set_search_query("".into());
    window.set_has_active_search(false);
    window.set_active_collection_id("".into());
    if let Ok(mut active_col) = active_collection_id.lock() {
        *active_col = None;
    }

    let collection_state = CollectionTreeState::from_collections(&result.collections);
    window.set_collection_tree_rows(collection_state.to_model());

    let item_rows: Vec<VaultItemUiState> = result
        .items
        .into_iter()
        .map(|item| VaultItemUiState {
            label: item.label,
            fields: item
                .fields
                .into_iter()
                .map(|field| (field.label, field.value))
                .collect(),
            collection_ids: item.collection_ids,
        })
        .collect();

    let visible_indices: Vec<usize> = (0..item_rows.len()).collect();
    window.set_vault_item_rows(model_from_item_rows(&item_rows, &visible_indices));

    if item_rows.is_empty() {
        window.set_selected_vault_item_index(-1);
        window.set_selected_vault_item_title("".into());
        window.set_selected_vault_item_fields(ModelRc::new(
            VecModel::<crate::VaultItemFieldRow>::default(),
        ));
        window.set_selected_vault_item_empty_text("No vault items loaded.".into());
        window.set_selected_has_password(false);
        window.set_is_password_visible(false);
    } else {
        let is_pw_visible = password_visible_state
            .lock()
            .map(|mut s| {
                *s = false;
                false
            })
            .unwrap_or(false);
        apply_selected_item(window, 0, &item_rows[0], is_pw_visible);
    }

    if let Ok(mut state) = tree_state.lock() {
        *state = Some(collection_state);
    }
    if let Ok(mut items) = vault_item_state.lock() {
        *items = item_rows;
    }
    if let Ok(mut visible_ref) = visible_item_indices.lock() {
        *visible_ref = visible_indices;
    }
    window.set_is_vault_view(true);
}

fn schedule_tde_approval_poll(
    weak_window: slint::Weak<crate::MainWindow>,
    tde_pending_state: Arc<Mutex<Option<TdePendingState>>>,
    tree_state: Arc<Mutex<Option<CollectionTreeState>>>,
    vault_item_state: Arc<Mutex<Vec<VaultItemUiState>>>,
    visible_item_indices_state: Arc<Mutex<Vec<usize>>>,
    password_visible_state: Arc<Mutex<bool>>,
    active_collection_id: Arc<Mutex<Option<String>>>,
) {
    slint::Timer::single_shot(Duration::from_secs(10), move || {
        // Only poll if there is a pending TDE state and the window still
        // shows the approval-waiting view.
        let pending_snapshot = {
            if let Ok(guard) = tde_pending_state.lock() {
                guard.clone()
            } else {
                None
            }
        };

        if let Some(pending) = pending_snapshot {
            // Do the network poll on a background thread to avoid blocking
            // the Slint event loop.
            let tde_pending_state_inner = tde_pending_state.clone();
            let weak_for_poll = weak_window.clone();
            let tree_state_poll = tree_state.clone();
            let vault_item_state_poll = vault_item_state.clone();
            let visible_item_indices_poll = visible_item_indices_state.clone();
            let password_visible_state_poll = password_visible_state.clone();
            let active_collection_id_poll = active_collection_id.clone();

            thread::spawn(move || {
                let poll_result = crate::auth::poll_auth_request_approval(&pending);

                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(window) = weak_for_poll.upgrade() {
                        // If the TDE view is no longer showing, do nothing
                        if !window.get_is_tde_awaiting_approval() {
                            return;
                        }

                        match poll_result {
                            Ok(Some(encrypted_user_key)) => {
                                // Approval received — complete the flow
                                window
                                    .set_status_text("Approval received! Decrypting vault…".into());
                                window.set_status_is_error(false);

                                let tde_pending_for_thread = tde_pending_state_inner.clone();
                                let weak_for_complete = window.as_weak();
                                let tree_state_c = tree_state_poll.clone();
                                let vault_item_state_c = vault_item_state_poll.clone();
                                let visible_item_indices_c = visible_item_indices_poll.clone();
                                let password_visible_state_c = password_visible_state_poll.clone();
                                let active_collection_id_c = active_collection_id_poll.clone();

                                thread::spawn(move || {
                                    let pending_snap = {
                                        tde_pending_for_thread
                                            .lock()
                                            .ok()
                                            .and_then(|mut g| g.take())
                                    };
                                    let Some(pending) = pending_snap else {
                                        return;
                                    };

                                    let result = crate::auth::complete_tde_after_approval(
                                        &pending,
                                        &encrypted_user_key,
                                    );

                                    let _ = slint::invoke_from_event_loop(move || {
                                        if let Some(window) = weak_for_complete.upgrade() {
                                            match result {
                                                Ok(login_result) => {
                                                    populate_vault_after_login(
                                                        &window,
                                                        login_result,
                                                        "SSO login successful (device approved). Loaded {} collections and {} items.",
                                                        &tree_state_c,
                                                        &vault_item_state_c,
                                                        &visible_item_indices_c,
                                                        &password_visible_state_c,
                                                        &active_collection_id_c,
                                                    );
                                                }
                                                Err(e) => {
                                                    window.set_status_is_error(true);
                                                    window.set_status_text(e.into());
                                                }
                                            }
                                        }
                                    });
                                });
                            }
                            Ok(None) => {
                                // Not yet approved — reschedule
                                schedule_tde_approval_poll(
                                    weak_window,
                                    tde_pending_state_inner,
                                    tree_state_poll,
                                    vault_item_state_poll,
                                    visible_item_indices_poll,
                                    password_visible_state_poll,
                                    active_collection_id_poll,
                                );
                            }
                            Err(e) => {
                                eprintln!("TDE poll error (will retry): {e}");
                                schedule_tde_approval_poll(
                                    weak_window,
                                    tde_pending_state_inner,
                                    tree_state_poll,
                                    vault_item_state_poll,
                                    visible_item_indices_poll,
                                    password_visible_state_poll,
                                    active_collection_id_poll,
                                );
                            }
                        }
                    }
                });
            });
        } else {
            // No pending TDE state, but keep the timer alive in case SSO is
            // triggered later in this session.
            schedule_tde_approval_poll(
                weak_window,
                tde_pending_state,
                tree_state,
                vault_item_state,
                visible_item_indices_state,
                password_visible_state,
                active_collection_id,
            );
        }
    });
}

fn schedule_totp_refresh(
    weak_window: slint::Weak<crate::MainWindow>,
    vault_item_state: Arc<Mutex<Vec<VaultItemUiState>>>,
    visible_item_indices_state: Arc<Mutex<Vec<usize>>>,
    password_visible_state: Arc<Mutex<bool>>,
) {
    slint::Timer::single_shot(Duration::from_secs(1), move || {
        if let Some(window) = weak_window.upgrade() {
            let selected_index = window.get_selected_vault_item_index();
            if let Ok(selected_index) = usize::try_from(selected_index) {
                let source_index =
                    visible_item_indices_state
                        .lock()
                        .ok()
                        .and_then(|visible_indices_ref| {
                            visible_indices_ref.get(selected_index).copied()
                        });

                if let Some(source_index) = source_index {
                    if let Ok(items_ref) = vault_item_state.lock() {
                        if let Some(item) = items_ref.get(source_index) {
                            let is_password_visible = password_visible_state
                                .lock()
                                .map(|state| *state)
                                .unwrap_or(false);
                            apply_selected_item(&window, selected_index, item, is_password_visible);
                        }
                    }
                }
            }
        }

        schedule_totp_refresh(
            weak_window,
            vault_item_state,
            visible_item_indices_state,
            password_visible_state,
        );
    });
}

#[cfg(test)]
mod tests {
    use super::{
        VaultItemUiState, build_visible_item_indices, decode_base32_secret, generate_totp_code,
        parse_totp_config,
    };

    #[test]
    fn generates_known_totp_vector_sha1() {
        let secret = decode_base32_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        let code = generate_totp_code(&secret, 8, 30, 59, "SHA1").unwrap();
        assert_eq!(code, "94287082");
    }

    #[test]
    fn parses_otpauth_with_query_params() {
        let config = parse_totp_config(
            "otpauth://totp/Example:test?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30",
        )
        .unwrap();

        assert_eq!(config.digits, 6);
        assert_eq!(config.period, 30);
        assert_eq!(config.algorithm, "SHA1");
        assert!(!config.secret.is_empty());
    }

    #[test]
    fn search_matches_non_sensitive_fields_only() {
        let items = vec![
            VaultItemUiState {
                label: "Example".to_string(),
                fields: vec![
                    (
                        "Login / Username".to_string(),
                        "alice@example.com".to_string(),
                    ),
                    (
                        "Login / Password".to_string(),
                        "secret-password".to_string(),
                    ),
                    ("Login / Totp".to_string(), "JBSWY3DPEHPK3PXP".to_string()),
                    ("Login / Notes".to_string(), "prod account".to_string()),
                ],
                collection_ids: vec![],
            },
            VaultItemUiState {
                label: "Dev".to_string(),
                fields: vec![("Custom / Team".to_string(), "platform".to_string())],
                collection_ids: vec![],
            },
        ];

        assert_eq!(build_visible_item_indices(&items, "alice", None), vec![0]);
        assert_eq!(build_visible_item_indices(&items, "prod", None), vec![0]);
        assert_eq!(
            build_visible_item_indices(&items, "platform", None),
            vec![1]
        );
        assert_eq!(
            build_visible_item_indices(&items, "secret-password", None),
            Vec::<usize>::new()
        );
        assert_eq!(
            build_visible_item_indices(&items, "JBSWY3DPEHPK3PXP", None),
            Vec::<usize>::new()
        );
    }
}
