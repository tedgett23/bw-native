use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PreloginResponse {
    #[serde(alias = "Kdf")]
    pub(crate) kdf: Option<u32>,
    #[serde(alias = "KdfIterations")]
    pub(crate) kdf_iterations: Option<u32>,
    #[serde(alias = "KdfMemory")]
    pub(crate) kdf_memory: Option<u32>,
    #[serde(alias = "KdfParallelism")]
    pub(crate) kdf_parallelism: Option<u32>,
}

#[derive(Debug, Serialize)]
pub(super) struct PreloginRequest<'a> {
    pub(super) email: &'a str,
}

#[derive(Debug, Deserialize)]
pub(super) struct TokenSuccessResponse {
    #[serde(alias = "accessToken")]
    pub(super) access_token: Option<String>,
    #[serde(alias = "Key")]
    pub(super) key: Option<String>,
    #[serde(alias = "Kdf", default)]
    pub(super) kdf: Option<u32>,
    #[serde(alias = "KdfIterations", default)]
    pub(super) kdf_iterations: Option<u32>,
    #[serde(alias = "KdfMemory", default)]
    pub(super) kdf_memory: Option<u32>,
    #[serde(alias = "KdfParallelism", default)]
    pub(super) kdf_parallelism: Option<u32>,
    #[serde(alias = "UserDecryptionOptions", default)]
    pub(super) user_decryption_options: Option<UserDecryptionOptions>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UserDecryptionOptions {
    #[serde(alias = "HasMasterPassword", default)]
    pub(super) has_master_password: bool,
    #[allow(dead_code)]
    #[serde(alias = "KeyConnectorOption", default)]
    pub(super) key_connector_option: Option<KeyConnectorOption>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct KeyConnectorOption {
    #[serde(alias = "KeyConnectorUrl")]
    pub(super) key_connector_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TokenErrorResponse {
    pub(super) error: Option<String>,
    pub(super) error_description: Option<String>,
    pub(super) message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SsoPreValidateResponse {
    #[serde(alias = "Token")]
    pub(super) token: Option<String>,
}
