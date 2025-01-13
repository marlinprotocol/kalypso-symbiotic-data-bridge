use anyhow::Result;
use ethers::abi::{Abi, Token};
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{Address, Eip1559TransactionRequest, H160, H256, U256};
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::from_str;

pub const MIN_NUMBER_OF_RPC_RESPONSES: usize = 1;
pub const LATEST_BLOCK_MAX_VALIDITY: u64 = 60; // in seconds
pub const LATEST_BLOCK_ESTIMATION_BUFFER: u64 = 35;
pub const OPERATOR_BATCH_SIZE: usize = 80; // for salmon network

pub struct ConfigManager {
    pub path: String,
}

// Config struct containing the data bridge configuration parameters
#[derive(Debug, Deserialize)]
pub struct Config {
    pub chain_id: u64,
    pub kalypso_subnetwork: H256,
    pub http_rpc_urls: Vec<String>,
    pub kalypso_middleware_addr: Address,
    pub enclave_signer_file: String,
}

// App data struct containing the necessary fields to run the data bridge
#[derive(Debug)]
pub struct AppState {
    pub chain_id: u64,
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

// Endpoint parameters required for getting the stakes data from the symbiotic contracts
#[derive(Debug, Deserialize)]
pub struct SignStakeRequest {
    pub rpc_api_keys: Vec<String>,
    pub no_of_txs: usize,
    pub block_number: Option<u64>,
}

// Endpoint parameters required for getting the slash data from the symbiotic contracts
#[derive(Debug, Deserialize)]
pub struct SignSlashRequest {
    pub rpc_api_keys: Vec<String>,
    pub no_of_txs: usize,
    pub capture_timestamp: u64,
    pub to_block_number: Option<u64>,
}

// Vault snapshot struct submitted on the L2 'SymbioticStaking' contract
#[derive(Debug, Clone)]
pub struct VaultSnapshot {
    pub operator: Address,
    pub vault: Address,
    pub stake_token: Address,
    pub stake_amount: U256,
}

// Job slashed struct submitted on the L2 'SymbioticStaking' contract
#[derive(Debug, Clone)]
pub struct JobSlashed {
    pub job_id: U256,
    pub operator: Address,
    pub reward_address: Address,
}

// Signed data struct returned in the endpoint response
#[derive(Debug, Serialize)]
pub struct SignedData {
    pub data: String,
    pub signature: String,
}

// Enum defining the required state read methods to be called
#[derive(Debug, Clone, PartialEq)]
pub enum ViewTxnData {
    GetVaults,
    GetDelegate(Address),
    Collateral,
    Delegator,
    Slasher,
    OperatorVaultOptInService,
    OperatorNetworkOptInService,
    StakeAt(H256, Address, u64),
    WhoRegistry,
    IsOptedIn(Address, Address),
    TotalEntities,
    Entity(U256),
}

// Enum -> Method name (on the smart contracts) mapping
impl ViewTxnData {
    pub fn as_str(&self) -> &str {
        match &self {
            ViewTxnData::GetVaults => "getVaults",
            ViewTxnData::GetDelegate(_) => "getDelegate",
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

// Loads contract ABI from the json representation
pub fn load_abi_from_json(json_abi: &str) -> Result<Abi> {
    let contract: Abi = from_str(&json_abi)?;
    Ok(contract)
}

// Function to return the txn data based on the txn type received, using the contract Abi object
pub fn generate_txn(
    contract_addr: H160,
    contract_abi: &Abi,
    view_txn_data: ViewTxnData,
) -> Result<TypedTransaction> {
    // Get the encoding 'Function' object for the transaction type
    let function = contract_abi.function(view_txn_data.as_str())?;

    // Encode the params into token list based on the txn type
    let params = match view_txn_data {
        ViewTxnData::GetVaults
        | ViewTxnData::Collateral
        | ViewTxnData::Delegator
        | ViewTxnData::Slasher
        | ViewTxnData::OperatorVaultOptInService
        | ViewTxnData::OperatorNetworkOptInService
        | ViewTxnData::WhoRegistry
        | ViewTxnData::TotalEntities => vec![],
        ViewTxnData::GetDelegate(operator) => vec![Token::Address(operator)],
        ViewTxnData::Entity(ind) => vec![Token::Uint(ind.to_owned())],
        ViewTxnData::IsOptedIn(who, wher) => vec![Token::Address(who), Token::Address(wher)],
        ViewTxnData::StakeAt(subnetwork, operator, timestamp) => vec![
            Token::FixedBytes(subnetwork.to_fixed_bytes().to_vec()),
            Token::Address(operator),
            Token::Uint(timestamp.into()),
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
