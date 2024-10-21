use anyhow::Result;
use ethers::abi::{Abi, Token};
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{Address, Eip1559TransactionRequest, H160, H256, U256};
use k256::ecdsa::SigningKey;
use serde::Deserialize;
use serde_json::from_str;

pub struct ConfigManager {
    pub path: String,
}

// Config struct containing the data bridge configuration parameters
#[derive(Debug, Deserialize)]
pub struct Config {
    pub mainnet_chain_id: u64,
    pub kalypso_subnetwork: H256,
    pub http_rpc_urls: Vec<String>,
    pub kalypso_middleware_addr: Address,
    pub enclave_signer_file: String,
}

// App data struct containing the necessary fields to run the data bridge
#[derive(Debug)]
pub struct AppState {
    pub mainnet_chain_id: u64,
    pub kalypso_subnetwork: H256,
    pub http_rpc_urls: Vec<String>,
    pub kalypso_middleware_addr: Address,
    pub kalypso_middleware_abi: Abi,
    pub vault_abi: Abi,
    pub vault_storage_abi: Abi,
    pub base_delegator_abi: Abi,
    pub opt_in_service_abi: Abi,
    pub registry_abi: Abi,
    pub enclave_signer: SigningKey,
}

#[derive(Debug, Deserialize)]
pub struct SignStakeRequest {
    pub rpc_api_keys: Vec<String>,
    pub stakes_txn_size: usize,
    pub capture_timestamp: usize,
    pub block_number: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct VaultSnapshot {
    pub operator: Address,
    pub vault: Address,
    pub stake_token: Address,
    pub stake_amount: U256,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ViewTxnType {
    GetVaults,
    Collateral,
    Delegator,
    OperatorVaultOptInService,
    OperatorNetworkOptInService,
    StakeAt,
    WhoRegistry,
    IsOptedIn,
    TotalEntities,
    Entity,
}

impl ViewTxnType {
    pub fn as_str(&self) -> &str {
        match self {
            ViewTxnType::GetVaults => "getVaults",
            ViewTxnType::Collateral => "collateral",
            ViewTxnType::Delegator => "delegator",
            ViewTxnType::OperatorVaultOptInService => "OPERATOR_VAULT_OPT_IN_SERVICE",
            ViewTxnType::OperatorNetworkOptInService => "OPERATOR_NETWORK_OPT_IN_SERVICE",
            ViewTxnType::StakeAt => "stakeAt",
            ViewTxnType::WhoRegistry => "WHO_REGISTRY",
            ViewTxnType::IsOptedIn => "isOptedIn",
            ViewTxnType::TotalEntities => "totalEntities",
            ViewTxnType::Entity => "entity",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ViewTxnMetadata {
    pub txn_type: ViewTxnType,
    pub entity_data: Option<U256>,
    pub is_opted_in_data: Option<(Address, Address)>,
    pub stake_at_data: Option<(H256, Address, usize)>,
}

pub fn load_abi_from_json(json_abi: &str) -> Result<Abi> {
    let contract: Abi = from_str(&json_abi)?;
    Ok(contract)
}

// Function to return the txn data based on the txn type received, using the contract Abi object
pub fn generate_txn(
    contract_addr: H160,
    contract_abi: &Abi,
    view_txn_metadata: &ViewTxnMetadata,
) -> Result<TypedTransaction> {
    // Get the encoding 'Function' object for the transaction type
    let function = contract_abi.function(view_txn_metadata.txn_type.as_str())?;

    let params = match view_txn_metadata.txn_type {
        ViewTxnType::GetVaults
        | ViewTxnType::Collateral
        | ViewTxnType::Delegator
        | ViewTxnType::OperatorVaultOptInService
        | ViewTxnType::OperatorNetworkOptInService
        | ViewTxnType::WhoRegistry
        | ViewTxnType::TotalEntities => vec![],
        ViewTxnType::Entity => vec![Token::Uint(view_txn_metadata.entity_data.unwrap())],
        ViewTxnType::IsOptedIn => {
            let param_data = view_txn_metadata.is_opted_in_data.unwrap();

            vec![Token::Address(param_data.0), Token::Address(param_data.1)]
        }
        ViewTxnType::StakeAt => {
            let param_data = view_txn_metadata.stake_at_data.unwrap();

            vec![
                Token::FixedBytes(param_data.0.to_fixed_bytes().to_vec()),
                Token::Address(param_data.1),
                Token::Uint(param_data.2.into()),
                Token::Bytes(vec![]),
            ]
        }
    };

    let txn_data = function.encode_input(&params)?;

    // Return the TransactionRequest object using the encoded data and contract address
    Ok(TypedTransaction::Eip1559(Eip1559TransactionRequest {
        to: Some(contract_addr.into()),
        data: Some(txn_data.into()),
        ..Default::default()
    }))
}

// Conversion function for H256 TxHash type to Address type
pub fn h256_to_address(hash: H256) -> Address {
    Address::from_slice(&hash.as_bytes()[12..]) // Extract last 20 bytes
}
