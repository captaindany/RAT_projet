use crate::Error;

/// C2 server URL. Override with SERVER_URL env var.
pub const DEFAULT_SERVER_URL: &str = "http://127.0.0.1:8080";

/// Client CLI configuration loaded from environment variables.
#[derive(Debug)]
pub struct Config {
    pub server_url: String,
    pub identity_public_key: ed25519_dalek::PublicKey,
    pub identity_private_key: ed25519_dalek::SecretKey,
}

impl Config {
    pub fn load() -> Result<Config, Error> {
        dotenv::dotenv().ok();

        let server_url = std::env::var("SERVER_URL")
            .unwrap_or_else(|_| DEFAULT_SERVER_URL.to_string());

        // Load identity private key from env var (base64-encoded)
        let private_key_b64 = std::env::var("IDENTITY_PRIVATE_KEY").map_err(|_| {
            Error::Internal(
                "IDENTITY_PRIVATE_KEY env var is not set. \
                 Run `client identity` to generate a keypair, then set the env var."
                    .to_string(),
            )
        })?;

        let private_key_bytes = base64::decode(&private_key_b64)
            .map_err(|e| Error::Internal(format!("IDENTITY_PRIVATE_KEY decode error: {}", e)))?;

        let identity_private_key = ed25519_dalek::SecretKey::from_bytes(&private_key_bytes)
            .map_err(|e| Error::Internal(format!("IDENTITY_PRIVATE_KEY parse error: {}", e)))?;

        let identity_public_key: ed25519_dalek::PublicKey = (&identity_private_key).into();

        Ok(Config {
            server_url,
            identity_public_key,
            identity_private_key,
        })
    }
}

// ── Re-export for modules that use the constant directly ─────────────────────
pub fn server_url() -> String {
    std::env::var("SERVER_URL").unwrap_or_else(|_| DEFAULT_SERVER_URL.to_string())
}
