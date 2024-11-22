use anyhow::Result;
use ethers::abi::{Abi, Token};
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{Address, Eip1559TransactionRequest, H160, H256, U256};
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::from_str;

// Average Ethereum block time in seconds (adjust this value as needed)
pub const AVERAGE_BLOCK_TIME: u64 = 12;
pub const BLOCK_ESTIMATION_BUFFER: u64 = 10_000;

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
    pub base_delegator_abi: Abi,
    pub opt_in_service_abi: Abi,
    pub registry_abi: Abi,
    pub enclave_signer: SigningKey,
}

#[derive(Debug, Deserialize)]
pub struct SignStakeRequest {
    pub rpc_api_keys: Vec<String>,
    pub no_of_txs: usize,
    pub capture_timestamp: usize,
    pub block_number: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct SignSlashRequest {
    pub rpc_api_keys: Vec<String>,
    pub no_of_txs: usize,
    pub capture_timestamp: usize,
    pub last_capture_timestamp: usize,
    pub from_block_number: Option<usize>,
    pub to_block_number: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct VaultSnapshot {
    pub operator: Address,
    pub vault: Address,
    pub stake_token: Address,
    pub stake_amount: U256,
}

#[derive(Debug, Clone)]
pub struct JobSlashed {
    pub job_id: U256,
    pub operator: Address,
    pub reward_address: Address,
}

#[derive(Debug, Serialize)]
pub struct SignedData {
    pub data: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ViewTxnData {
    GetVaults,
    Collateral,
    Delegator,
    Slasher,
    OperatorVaultOptInService,
    OperatorNetworkOptInService,
    StakeAt(H256, Address, usize),
    WhoRegistry,
    IsOptedIn(Address, Address),
    TotalEntities,
    Entity(U256),
}

impl ViewTxnData {
    pub fn as_str(&self) -> &str {
        match &self {
            ViewTxnData::GetVaults => "getVaults",
            ViewTxnData::Collateral => "collateral",
            ViewTxnData::Delegator => "delegator",
            ViewTxnData::Slasher => "slasher",
            ViewTxnData::OperatorVaultOptInService => "OPERATOR_VAULT_OPT_IN_SERVICE",
            ViewTxnData::OperatorNetworkOptInService => "OPERATOR_NETWORK_OPT_IN_SERVICE",
            ViewTxnData::StakeAt(_, _, _) => "stakeAt",
            ViewTxnData::WhoRegistry => "WHO_REGISTRY",
            ViewTxnData::IsOptedIn(_, _) => "isOptedIn",
            ViewTxnData::TotalEntities => "totalEntities",
            ViewTxnData::Entity(_) => "entity",
        }
    }
}

pub fn load_abi_from_json(json_abi: &str) -> Result<Abi> {
    let contract: Abi = from_str(&json_abi)?;
    Ok(contract)
}

// Function to return the txn data based on the txn type received, using the contract Abi object
pub fn generate_txn(
    contract_addr: H160,
    contract_abi: &Abi,
    view_txn_data: &ViewTxnData,
) -> Result<TypedTransaction> {
    // Get the encoding 'Function' object for the transaction type
    let function = contract_abi.function(view_txn_data.as_str())?;

    let params = match view_txn_data {
        ViewTxnData::GetVaults
        | ViewTxnData::Collateral
        | ViewTxnData::Delegator
        | ViewTxnData::Slasher
        | ViewTxnData::OperatorVaultOptInService
        | ViewTxnData::OperatorNetworkOptInService
        | ViewTxnData::WhoRegistry
        | ViewTxnData::TotalEntities => vec![],
        ViewTxnData::Entity(ind) => vec![Token::Uint(ind.to_owned())],
        ViewTxnData::IsOptedIn(who, wher) => vec![
            Token::Address(who.to_owned()),
            Token::Address(wher.to_owned()),
        ],
        ViewTxnData::StakeAt(subnetwork, operator, timestamp) => vec![
            Token::FixedBytes(subnetwork.to_fixed_bytes().to_vec()),
            Token::Address(operator.to_owned()),
            Token::Uint(timestamp.to_owned().into()),
            Token::Bytes(vec![]),
        ],
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
    Address::from_slice(&hash.as_bytes()[0..20])
}
