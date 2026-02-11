use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};
use std::thread;

use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

fn model_from_strings(items: Vec<String>) -> ModelRc<SharedString> {
    let rows: Vec<SharedString> = items.into_iter().map(SharedString::from).collect();
    ModelRc::new(VecModel::from(rows))
}

#[derive(Default)]
struct TreeNode {
    children: BTreeMap<String, TreeNode>,
}

struct CollectionTreeState {
    root: TreeNode,
    expanded_nodes: HashSet<String>,
    visible_rows: Vec<crate::CollectionTreeRow>,
}

impl CollectionTreeState {
    fn from_paths(paths: &[String]) -> Self {
        let mut root = TreeNode::default();

        for path in paths {
            let mut node = &mut root;
            for part in path.split('/').filter(|part| !part.is_empty()) {
                node = node.children.entry(part.to_string()).or_default();
            }
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

    fn to_model(&self) -> ModelRc<crate::CollectionTreeRow> {
        ModelRc::new(VecModel::from(self.visible_rows.clone()))
    }

    fn rebuild_rows(&mut self) {
        let mut rows = Vec::new();
        flatten_tree(&self.root, "", 0, &self.expanded_nodes, &mut rows);
        self.visible_rows = rows;
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

    {
        let weak_window = weak_window.clone();
        let tree_state = tree_state.clone();

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

            state.toggle_row(row_index);
            window.set_collection_tree_rows(state.to_model());
        });
    }

    window.on_login_requested(move || {
        let Some(window) = weak_window.upgrade() else {
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
        window.set_collection_tree_rows(ModelRc::new(
            VecModel::<crate::CollectionTreeRow>::default(),
        ));
        window.set_vault_items(ModelRc::new(VecModel::<SharedString>::default()));
        if let Ok(mut state) = tree_state.lock() {
            *state = None;
        }

        let weak_for_thread = weak_window.clone();
        let tree_state = tree_state.clone();
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
                                CollectionTreeState::from_paths(&result.collections);
                            window.set_collection_tree_rows(collection_state.to_model());
                            window.set_vault_items(model_from_strings(result.items));
                            if let Ok(mut state) = tree_state.lock() {
                                *state = Some(collection_state);
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
}
