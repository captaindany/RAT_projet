use crate::Error;
use common::crypto;
use std::path::PathBuf;

// ── Identifiers ──────────────────────────────────────────────────────────────
pub const AGENT_INSTALL_FILE: &str = "ch13_agent";
pub const SINGLE_INSTANCE_IDENTIFIER: &str = "ch13_agent";
pub const INSTALL_DIRECTORY: &str = "bhr_ch13";

// ── C2 Server URL ─────────────────────────────────────────────────────────────
/// Override via SERVER_URL env var; defaults to localhost for lab use.
pub const DEFAULT_SERVER_URL: &str = "http://127.0.0.1:8080";

// ── Crypto keys (base64-encoded, pre-generated for lab) ──────────────────────
/// Agent identity private key (Ed25519). Set via AGENT_IDENTITY_PRIVATE_KEY env var.
/// Generate with: cargo run --bin client -- identity
pub const DEFAULT_AGENT_IDENTITY_PRIVATE_KEY: &str = "";

/// Agent pre-key private key (X25519). Set via AGENT_PREKEY_PRIVATE_KEY env var.
pub const DEFAULT_AGENT_PREKEY_PRIVATE_KEY: &str = "";

/// Operator (client) identity public key (Ed25519). Set via CLIENT_IDENTITY_PUBLIC_KEY env var.
/// Must match the key configured on the server.
pub const DEFAULT_CLIENT_IDENTITY_PUBLIC_KEY: &str = "";

// ── Config struct ─────────────────────────────────────────────────────────────
pub struct Config {
    pub identity_public_key: ed25519_dalek::PublicKey,
    pub identity_private_key: ed25519_dalek::SecretKey,
    pub private_prekey: [u8; crypto::X25519_PRIVATE_KEY_SIZE],
    pub client_identity_public_key: ed25519_dalek::PublicKey,
    pub server_url: String,
}

impl Config {
    pub fn load() -> Result<Config, Error> {
        dotenv::dotenv().ok();

        let server_url = std::env::var("SERVER_URL")
            .unwrap_or_else(|_| DEFAULT_SERVER_URL.to_string());

        // Agent identity keypair
        let identity_private_key_b64 = std::env::var("AGENT_IDENTITY_PRIVATE_KEY")
            .unwrap_or_else(|_| DEFAULT_AGENT_IDENTITY_PRIVATE_KEY.to_string());
        let identity_private_key_bytes = base64::decode(&identity_private_key_b64)
            .map_err(|e| Error::Internal(format!("AGENT_IDENTITY_PRIVATE_KEY decode error: {}", e)))?;
        let identity_private_key = ed25519_dalek::SecretKey::from_bytes(&identity_private_key_bytes)
            .map_err(|e| Error::Internal(format!("AGENT_IDENTITY_PRIVATE_KEY parse error: {}", e)))?;
        let identity_public_key: ed25519_dalek::PublicKey = (&identity_private_key).into();

        // Agent pre-key (X25519)
        let prekey_b64 = std::env::var("AGENT_PREKEY_PRIVATE_KEY")
            .unwrap_or_else(|_| DEFAULT_AGENT_PREKEY_PRIVATE_KEY.to_string());
        let prekey_bytes = base64::decode(&prekey_b64)
            .map_err(|e| Error::Internal(format!("AGENT_PREKEY_PRIVATE_KEY decode error: {}", e)))?;
        let mut private_prekey = [0u8; crypto::X25519_PRIVATE_KEY_SIZE];
        if prekey_bytes.len() == crypto::X25519_PRIVATE_KEY_SIZE {
            private_prekey.copy_from_slice(&prekey_bytes);
        }

        // Operator (client) identity public key
        let client_key_b64 = std::env::var("CLIENT_IDENTITY_PUBLIC_KEY")
            .unwrap_or_else(|_| DEFAULT_CLIENT_IDENTITY_PUBLIC_KEY.to_string());
        let client_key_bytes = base64::decode(&client_key_b64)
            .map_err(|e| Error::Internal(format!("CLIENT_IDENTITY_PUBLIC_KEY decode error: {}", e)))?;
        let client_identity_public_key = ed25519_dalek::PublicKey::from_bytes(&client_key_bytes)
            .map_err(|e| Error::Internal(format!("CLIENT_IDENTITY_PUBLIC_KEY parse error: {}", e)))?;

        Ok(Config {
            identity_public_key,
            identity_private_key,
            private_prekey,
            client_identity_public_key,
            server_url,
        })
    }
}

// ── Path helpers ──────────────────────────────────────────────────────────────
pub fn get_agent_directory() -> Result<PathBuf, Error> {
    let mut data_dir = match dirs::data_dir() {
        Some(home_dir) => home_dir,
        None => return Err(Error::Internal("Error getting data directory.".to_string())),
    };
    data_dir.push(INSTALL_DIRECTORY);
    Ok(data_dir)
}

pub fn get_agent_install_target() -> Result<PathBuf, Error> {
    let mut install_target = get_agent_directory()?;
    install_target.push(AGENT_INSTALL_FILE);
    Ok(install_target)
}

// Re-export server URL for run.rs
pub fn server_url() -> String {
    std::env::var("SERVER_URL").unwrap_or_else(|_| DEFAULT_SERVER_URL.to_string())
}
