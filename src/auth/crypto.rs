use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};

use super::models::PreloginResponse;

const DEFAULT_PBKDF2_ITERATIONS: u32 = 600_000;
const DEFAULT_ARGON2_ITERATIONS: u32 = 3;
const DEFAULT_ARGON2_MEMORY_MIB: u32 = 64;
const DEFAULT_ARGON2_PARALLELISM: u32 = 4;

pub(super) enum KdfConfig {
    Pbkdf2 {
        iterations: u32,
    },
    Argon2id {
        iterations: u32,
        memory_mib: u32,
        parallelism: u32,
    },
}

pub(super) fn kdf_config_from_prelogin(prelogin: &PreloginResponse) -> Result<KdfConfig, String> {
    match prelogin.kdf.unwrap_or(0) {
        0 => Ok(KdfConfig::Pbkdf2 {
            iterations: prelogin
                .kdf_iterations
                .unwrap_or(DEFAULT_PBKDF2_ITERATIONS)
                .max(1),
        }),
        1 => Ok(KdfConfig::Argon2id {
            iterations: prelogin
                .kdf_iterations
                .unwrap_or(DEFAULT_ARGON2_ITERATIONS)
                .max(1),
            memory_mib: prelogin
                .kdf_memory
                .unwrap_or(DEFAULT_ARGON2_MEMORY_MIB)
                .max(1),
            parallelism: prelogin
                .kdf_parallelism
                .unwrap_or(DEFAULT_ARGON2_PARALLELISM)
                .max(1),
        }),
        unsupported => Err(format!("Unsupported KDF type from server: {unsupported}")),
    }
}

pub(super) fn derive_master_key(
    password: &str,
    normalized_email: &str,
    kdf: &KdfConfig,
) -> Result<[u8; 32], String> {
    let mut key = [0_u8; 32];

    match kdf {
        KdfConfig::Pbkdf2 { iterations } => {
            pbkdf2_hmac::<Sha256>(
                password.as_bytes(),
                normalized_email.as_bytes(),
                *iterations,
                &mut key,
            );
        }
        KdfConfig::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        } => {
            let salt = Sha256::digest(normalized_email.as_bytes());
            let memory_kib = memory_mib.saturating_mul(1024).max(8);
            let params = Params::new(memory_kib, *iterations, *parallelism, Some(32))
                .map_err(|error| format!("Invalid Argon2 parameters: {error}"))?;

            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            argon2
                .hash_password_into(password.as_bytes(), &salt, &mut key)
                .map_err(|error| format!("Failed to derive Argon2 key: {error}"))?;
        }
    }

    Ok(key)
}

pub(super) fn derive_password_hash(password: &str, master_key: &[u8; 32]) -> String {
    let mut password_hash = [0_u8; 32];
    pbkdf2_hmac::<Sha256>(master_key, password.as_bytes(), 1, &mut password_hash);
    BASE64_STANDARD.encode(password_hash)
}
