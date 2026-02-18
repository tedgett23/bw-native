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
    #[serde(alias = "TrustedDeviceOption", default)]
    pub(super) trusted_device_option: Option<TrustedDeviceOption>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct KeyConnectorOption {
    #[serde(alias = "KeyConnectorUrl")]
    pub(super) key_connector_url: Option<String>,
}

/// Fields present in `UserDecryptionOptions.trustedDeviceOption` when the org
/// uses Trusted Device Encryption (TDE) and the server believes this device
/// may already be trusted.
#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(super) struct TrustedDeviceOption {
    /// RSA private key encrypted with the local device key (AES-256-CBC).
    /// Present only if the server has a record of this device being trusted.
    #[serde(alias = "EncryptedPrivateKey", default)]
    pub(super) encrypted_private_key: Option<String>,
    /// User key encrypted with the device's RSA public key.
    /// Present only if the server has a record of this device being trusted.
    #[serde(alias = "EncryptedUserKey", default)]
    pub(super) encrypted_user_key: Option<String>,
    /// Whether an admin has previously approved this device.
    #[serde(alias = "HasAdminApproval", default)]
    pub(super) has_admin_approval: bool,
    /// Whether a trusted device (another session) has approved this device.
    #[serde(alias = "HasLoginApprovingDevice", default)]
    pub(super) has_login_approving_device: bool,
    /// Whether a manage-reset-password policy applies (informational).
    #[serde(alias = "HasManageResetPasswordPermission", default)]
    pub(super) has_manage_reset_password_permission: bool,
}

/// Response body from POST /auth-requests or POST /auth-requests/admin-request.
#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(super) struct AuthRequestResponse {
    pub(super) id: String,
    /// The public key we sent, echoed back (Base64).
    #[serde(default)]
    pub(super) public_key: Option<String>,
    /// Short fingerprint phrase displayed to the approver.
    #[serde(alias = "fingerprint", default)]
    pub(super) fingerprint_phrase: Option<String>,
}

/// Response body from GET /auth-requests/{id}/response — the approval payload.
#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(super) struct AuthRequestApprovalResponse {
    pub(super) id: String,
    /// True when the approver has approved the request.
    #[serde(default)]
    pub(super) approved: Option<bool>,
    /// The user key encrypted with our ephemeral RSA public key.
    /// Present only after approval.
    #[serde(alias = "key", default)]
    pub(super) encrypted_user_key: Option<String>,
    /// Device identifier of the approving device.
    #[serde(default)]
    pub(super) request_approved: Option<bool>,
}

/// Request body for POST /auth-requests.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CreateAuthRequest {
    pub(super) email: String,
    pub(super) public_key: String,
    pub(super) device_identifier: String,
    pub(super) access_code: String,
    pub(super) r#type: u32,
    pub(super) finger_print: String,
}

/// Request body for PUT /devices/identifier/{id}/trust.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TrustDeviceRequest {
    pub(super) name: String,
    pub(super) identifier: String,
    pub(super) r#type: u32,
    pub(super) encrypted_user_key: String,
    pub(super) encrypted_public_key: String,
    pub(super) encrypted_private_key: String,
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
