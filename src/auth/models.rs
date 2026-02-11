use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PreloginResponse {
    #[serde(alias = "Kdf")]
    pub(super) kdf: Option<u32>,
    #[serde(alias = "KdfIterations")]
    pub(super) kdf_iterations: Option<u32>,
    #[serde(alias = "KdfMemory")]
    pub(super) kdf_memory: Option<u32>,
    #[serde(alias = "KdfParallelism")]
    pub(super) kdf_parallelism: Option<u32>,
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
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TokenErrorResponse {
    pub(super) error: Option<String>,
    pub(super) error_description: Option<String>,
    pub(super) message: Option<String>,
}
