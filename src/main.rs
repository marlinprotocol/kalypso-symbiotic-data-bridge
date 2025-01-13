mod config;
mod contract_calls;
mod server;
mod signing;
mod utils;

use actix_web::web::Data;
use actix_web::{App, HttpServer};
use anyhow::{anyhow, Context, Result};
use clap::Parser;
use k256::ecdsa::SigningKey;
use tokio::fs;

use server::*;
use utils::{load_abi_from_json, AppState, ConfigManager, MIN_NUMBER_OF_RPC_RESPONSES};

// KALYPSO SYMBIOTIC DATA BRIDGE CONFIGURATION PARAMETERS
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    // Server port
    #[clap(long, value_parser, default_value = "6005")]
    port: u16,

    // Path to the main configuration file
    #[clap(
        long,
        value_parser,
        default_value = "./kalypso_symbiotic_data_bridge_config.json"
    )]
    config_file: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse the command line arguments and the main configuration file
    let args = Cli::parse();
    let config_manager = ConfigManager::new(&args.config_file);
    let config = config_manager.load_config().unwrap();

    // Make sure the number of RPC URLs configured is not less than the minimum number required to validate a response
    if config.http_rpc_urls.len() < MIN_NUMBER_OF_RPC_RESPONSES {
        return Err(anyhow!(
            "Provide at least {} RPC URLs!",
            MIN_NUMBER_OF_RPC_RESPONSES
        ));
    }

    // Read the 'secp256k1' private key of the enclave instance generated by the keygen
    let enclave_signer_key = SigningKey::from_slice(
        fs::read(config.enclave_signer_file)
            .await
            .context("Failed to read the enclave signer key")?
            .as_slice(),
    )
    .context("Invalid enclave signer key")?;

    // Initialize App data that will be shared across multiple threads and tasks
    let app_data = Data::new(AppState {
        chain_id: config.chain_id,
        kalypso_subnetwork: config.kalypso_subnetwork,
        http_rpc_urls: config.http_rpc_urls,
        kalypso_middleware_addr: config.kalypso_middleware_addr,
        kalypso_middleware_abi: load_abi_from_json(include_str!("../KalypsoMiddleware.json"))
            .context("Failed to deserialize 'KalypsoMiddleware' contract ABI")?,
        vault_abi: load_abi_from_json(include_str!("../IVault.json"))
            .context("Failed to deserialize 'IVault' contract ABI")?,
        base_delegator_abi: load_abi_from_json(include_str!("../IBaseDelegator.json"))
            .context("Failed to deserialize 'IBaseDelegator' contract ABI")?,
        opt_in_service_abi: load_abi_from_json(include_str!("../IOptInService.json"))
            .context("Failed to deserialize 'IOptInService' contract ABI")?,
        registry_abi: load_abi_from_json(include_str!("../IRegistry.json"))
            .context("Failed to deserialize 'IRegistry' contract ABI")?,
        enclave_signer: enclave_signer_key,
    });

    // Start actix server to expose the data bridge API endpoints outside the enclave
    let server = HttpServer::new(move || {
        App::new()
            .app_data(app_data.clone())
            .service(index)
            .service(read_and_sign_stakes)
            .service(read_and_sign_slashes)
    })
    .bind(("0.0.0.0", args.port))
    .context(format!("Could not bind to port {}", args.port))?
    .run();

    println!("Node server started on port {}", args.port);

    server.await?;

    Ok(())
}
