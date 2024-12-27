use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use actix_web::web::Data;
use anyhow::{anyhow, Context, Result};
use ethers::abi::{decode, Abi, ParamType};
use ethers::providers::{Http, Middleware, Provider};
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{Address, BlockNumber, Bytes, H160, U256};
use tokio::sync::mpsc::{self, Sender};
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use crate::utils::*;

// Method returning the mapping from RPC URLs to their corresponding block numbers and timestamps to configure while making state read calls
pub async fn get_block_number_and_timestamps(
    http_rpc_urls: Vec<String>,
    rpc_api_keys: Arc<Vec<String>>,
    block_number: Option<u64>,
) -> HashMap<String, (u64, u64)> {
    // Create a mpsc channel
    let (tx, mut rx) = mpsc::channel::<(String, u64, u64)>(10);

    for ind in 0..http_rpc_urls.len() {
        // Initialize the HTTP RPC URL with the corresponding API Key included
        let http_rpc_url = format!(
            "{}/{}",
            http_rpc_urls.get(ind).unwrap(),
            rpc_api_keys.get(ind).unwrap()
        );
        let tx_clone = tx.clone();

        // Spawn task independently to retrieve the block number and timestamp for a RPC endpoint
        tokio::spawn(async move {
            let mut block_num = block_number;

            // If block number is not specified, use the latest block
            if block_num.is_none() {
                // Retrieve latest block number and timestamp for the given RPC endpoint
                let Some(latest_block_metadata) = get_block_metadata(&http_rpc_url, None).await
                else {
                    return;
                };

                // Check whether the latest block for the RPC is older than the max validity configured to consider it
                if latest_block_metadata.1
                    < SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Time went backwards")
                        .as_secs()
                        .saturating_sub(LATEST_BLOCK_MAX_VALIDITY)
                {
                    return;
                }

                // Initialize the block number to be considered for reading the data from this RPC based on the estimation buffer (~7 mins old)
                block_num = Some(latest_block_metadata.0 - LATEST_BLOCK_ESTIMATION_BUFFER);
            }

            // Fetch the relevant block number and timestamp for the given RPC endpoint
            let Some(block_metadata) = get_block_metadata(&http_rpc_url, block_num.clone()).await
            else {
                return;
            };

            // Send this data to the receiver channel for collection
            let _ = tx_clone
                .send((http_rpc_url, block_metadata.0, block_metadata.1))
                .await;
        });
    }

    drop(tx);

    // Collect the RPC -> Block metadata map through the receiver channel
    let mut rpc_block_map = HashMap::new();
    while let Some((rpc, block_num, timestamp)) = rx.recv().await {
        rpc_block_map.insert(rpc, (block_num, timestamp));
    }

    rpc_block_map
}

// TODO: Get the vault addresses one-by-one by iterating over 'getNoOfVaults' and fetching 'vaults(index)'
// Method returning the vault addresses associated with the kalypso subnetwork
pub async fn get_vaults_addresses(
    rpc_block_map: HashMap<String, (u64, u64)>,
    app_state: Data<AppState>,
) -> Result<Vec<H160>> {
    // Fetch the vault addresses associated with the kalypso subnetwork from the 'KalypsoMiddleware' contract through the RPCs
    let Some(vault_addresses_encoded) = call_txn_with_rpcs(
        rpc_block_map,
        app_state.chain_id,
        app_state.kalypso_middleware_addr,
        &app_state.kalypso_middleware_abi,
        ViewTxnData::GetVaults,
    )
    .await
    else {
        return Err(anyhow!("Failed to fetch the vault addresses token"));
    };
    // Decode the vault addresses list from the RPC response
    let Some(vault_addresses) = decode(
        &[ParamType::Array(Box::new(ParamType::Address))],
        &vault_addresses_encoded,
    )
    .context("Failed to decode getVaults address list from rpc call response")?[0]
        .clone()
        .into_array()
    else {
        return Err(anyhow!("Failed to decode the getVaults address list"));
    };

    Ok(vault_addresses
        .into_iter()
        .filter_map(|token| token.into_address())
        .collect())
}

/*
  GET THE STAKES DATA ASSOCIATED WITH A VAULT FOR THE KALYPSO SUBNETWORK
  -> Get the stake token address of the vault
  -> Get the base delegator contract address of the vault
  -> Get the operator-vault-opt-in-service contract address from the delegator contract
  -> Get the operator-network-opt-in-service contract address from the delegator contract
  -> Get the operator registry (associated with the vault) contract address from the operator-vault-opt-in-service contract
  -> Get the total operator entities count from the operator registry contract
  -> Loop through each index from 0 to totalEntities, Collect the stake amount associated with the operator address at that index
*/
pub async fn get_stakes_data_for_vault(
    vault: &Address,
    rpc_block_map: HashMap<String, (u64, u64)>,
    app_state: Data<AppState>,
) -> Result<Vec<VaultSnapshot>> {
    // Fetch the stake token (collateral) associated with the vault contract through the RPCs
    let Some(stake_token_encoded) = call_txn_with_rpcs(
        rpc_block_map.clone(),
        app_state.chain_id,
        vault.clone(),
        &app_state.vault_abi,
        ViewTxnData::Collateral,
    )
    .await
    else {
        return Err(anyhow!("Failed to fetch the vault collateral token"));
    };
    // Decode the address from the RPC response
    let Some(stake_token) = decode(&[ParamType::Address], &stake_token_encoded)
        .context("Failed to decode stakeToken from rpc call response")?[0]
        .clone()
        .into_address()
    else {
        return Err(anyhow!("Failed to decode the stakeToken"));
    };

    // Fetch the base collateral from the vault contract through the RPCs
    let Some(delegator_encoded) = call_txn_with_rpcs(
        rpc_block_map.clone(),
        app_state.chain_id,
        vault.clone(),
        &app_state.vault_abi,
        ViewTxnData::Delegator,
    )
    .await
    else {
        return Err(anyhow!("Failed to fetch the vault delegator address"));
    };
    // Decode the address from the RPC response
    let Some(delegator) = decode(&[ParamType::Address], &delegator_encoded)
        .context("Failed to decode delegator from rpc call response")?[0]
        .clone()
        .into_address()
    else {
        return Err(anyhow!("Failed to decode the delegator"));
    };

    // Fetch the operator-vault-opt-in-service contract from the delegator contract through the RPCs
    let Some(operator_vault_opt_in_encoded) = call_txn_with_rpcs(
        rpc_block_map.clone(),
        app_state.chain_id,
        delegator.clone(),
        &app_state.base_delegator_abi,
        ViewTxnData::OperatorVaultOptInService,
    )
    .await
    else {
        return Err(anyhow!(
            "Failed to fetch the operator-vault-opt-in-service address"
        ));
    };
    // Decode the address from the RPC response
    let Some(operator_vault_opt_in_service) =
        decode(&[ParamType::Address], &operator_vault_opt_in_encoded)
            .context("Failed to decode operator-vault-opt-in-service from rpc call response")?[0]
            .clone()
            .into_address()
    else {
        return Err(anyhow!(
            "Failed to decode the operator-vault-opt-in-service address"
        ));
    };

    // Fetch the operator-network-opt-in-service contract from the delegator contract through the RPCs
    let Some(operator_network_opt_in_encoded) = call_txn_with_rpcs(
        rpc_block_map.clone(),
        app_state.chain_id,
        delegator.clone(),
        &app_state.base_delegator_abi,
        ViewTxnData::OperatorNetworkOptInService,
    )
    .await
    else {
        return Err(anyhow!(
            "Failed to fetch the operator-network-opt-in-service address"
        ));
    };
    // Decode the address from the RPC response
    let Some(operator_network_opt_in_service) =
        decode(&[ParamType::Address], &operator_network_opt_in_encoded)
            .context("Failed to decode operator-network-opt-in-service from rpc call response")?[0]
            .clone()
            .into_address()
    else {
        return Err(anyhow!(
            "Failed to decode the operator-network-opt-in-service address"
        ));
    };

    // Fetch the operator registry contract from the operator-vault-opt-in-service contract through the RPCs
    let Some(operator_registry_encoded) = call_txn_with_rpcs(
        rpc_block_map.clone(),
        app_state.chain_id,
        operator_vault_opt_in_service.clone(),
        &app_state.opt_in_service_abi,
        ViewTxnData::WhoRegistry,
    )
    .await
    else {
        return Err(anyhow!("Failed to fetch the operator registry address"));
    };
    // Decode the address from the RPC response
    let Some(operator_registry) = decode(&[ParamType::Address], &operator_registry_encoded)
        .context("Failed to decode operator registry from rpc call response")?[0]
        .clone()
        .into_address()
    else {
        return Err(anyhow!("Failed to decode the operator registry address"));
    };

    // Fetch the total operator entities associated with the registry contract through the RPCs
    let Some(operator_entities_encoded) = call_txn_with_rpcs(
        rpc_block_map.clone(),
        app_state.chain_id,
        operator_registry.clone(),
        &app_state.registry_abi,
        ViewTxnData::TotalEntities,
    )
    .await
    else {
        return Err(anyhow!("Failed to fetch the operator total entities"));
    };
    // Decode the count from the RPC response
    let Some(operator_entities) = decode(&[ParamType::Uint(256)], &operator_entities_encoded)
        .context("Failed to decode operator total entities from rpc call response")?[0]
        .clone()
        .into_uint()
    else {
        return Err(anyhow!("Failed to decode the operator total entities"));
    };

    // Create a mpsc channel
    let (tx, mut rx) = mpsc::channel::<Result<(H160, U256)>>(100);

    // For each operator in the registry, fetch their stake amount in the vault at the given timestamp if they are a part of the kalypso subnetwork
    let mut operator_ind = U256::zero();
    while operator_ind < operator_entities {
        let tx_clone = tx.clone();
        let vault_clone = vault.clone();
        let rpc_block_map_clone = rpc_block_map.clone();
        let app_state_clone = app_state.clone();

        tokio::spawn(async move {
            let _ = tx_clone
                .send(
                    get_stake_amount(
                        operator_ind,
                        vault_clone,
                        operator_registry,
                        operator_vault_opt_in_service,
                        operator_network_opt_in_service,
                        delegator,
                        rpc_block_map_clone,
                        app_state_clone,
                    )
                    .await,
                )
                .await;
        });

        operator_ind += U256::one();
    }

    drop(tx);

    // Collect the stake amounts of operators through the receiver channel receiving the data parallely
    let mut delegated_stakes: HashMap<H160, U256> = HashMap::new();
    while let Some(stake_amount) = rx.recv().await {
        let Ok((operator_delegate, stake_amount)) = stake_amount else {
            return Err(anyhow!(
                "Failed to fetch stake amount for an operator: {:?}",
                stake_amount.unwrap_err()
            ));
        };

        // If operator address is zero then skip it (isn't registered in the kalypso subnetwork)
        if operator_delegate.is_zero() {
            continue;
        }

        delegated_stakes
            .entry(operator_delegate)
            .and_modify(|stake| *stake += stake_amount)
            .or_insert(stake_amount);
    }

    Ok(delegated_stakes
        .iter()
        .map(|(&delegate, &stake)| VaultSnapshot {
            operator: delegate,
            vault: vault.clone(),
            stake_token: stake_token,
            stake_amount: stake,
        })
        .collect())
}

// pub async fn get_slash_data_for_vault(
//     vault: Address,
//     capture_timestamp: usize,
//     last_capture_timestamp: usize,
//     rpc_api_keys: &Vec<String>,
//     from_block_number: Option<usize>,
//     to_block_number: Option<usize>,
//     app_state: Data<AppState>,
// ) -> Result<Vec<JobSlashed>> {
//     let slasher_txn = generate_txn(vault.clone(), &app_state.vault_abi, &ViewTxnData::Slasher)
//         .context("Failed to generate transaction for vault slasher")?
//         .set_chain_id(app_state.chain_id)
//         .to_owned();

//     let Some(slasher_encoded) = call_tx_with_retries(
//         &app_state.http_rpc_urls,
//         rpc_api_keys,
//         slasher_txn,
//         to_block_number,
//     )
//     .await
//     else {
//         return Err(anyhow!("Failed to fetch the vault slasher address"));
//     };
//     let Some(slasher) = decode(&[ParamType::Address], &slasher_encoded)
//         .context("Failed to decode slasher from rpc call response")?[0]
//         .clone()
//         .into_address()
//     else {
//         return Err(anyhow!("Failed to decode the slasher"));
//     };

//     let mut approximate_from_block: Option<u64> = from_block_number.map(|num| num as u64);

//     if approximate_from_block.is_none() {
//         let Some((latest_block_number, latest_block_timestamp)) =
//             get_latest_block(&app_state.http_rpc_urls, rpc_api_keys).await
//         else {
//             return Err(anyhow!("Failed to fetch the latest block"));
//         };

//         // Calculate the difference in seconds between the target timestamp and the latest block timestamp
//         if (last_capture_timestamp as u64) > latest_block_timestamp {
//             return Err(anyhow!("Last capture timestamp is in the future"));
//         }
//         let time_diff = latest_block_timestamp - last_capture_timestamp as u64;

//         // Estimate how many blocks ago the target timestamp was
//         let blocks_ago = time_diff / AVERAGE_BLOCK_TIME;

//         // Calculate the approximate block number
//         approximate_from_block =
//             Some(latest_block_number.saturating_sub(blocks_ago + BLOCK_ESTIMATION_BUFFER));
//     }

//     let Some(approximate_from_block) = approximate_from_block else {
//         return Err(anyhow!(
//             "Failed to estimate from block number for getting event logs"
//         ));
//     };

//     let mut slash_filter = Filter::new()
//         .address(slasher)
//         .topic0(H256::from(keccak256(
//             "Slash(bytes32,address,uint256,uint48)",
//         )))
//         .topic1(H256::from(app_state.kalypso_subnetwork))
//         .from_block(approximate_from_block);

//     if to_block_number.is_some() {
//         slash_filter = slash_filter.to_block(to_block_number.clone().unwrap());
//     }

//     let Some(slash_logs) = get_logs(&app_state.http_rpc_urls, rpc_api_keys, slash_filter).await
//     else {
//         return Err(anyhow!(
//             "Failed to fetch logs for slashing from symbiotic slasher contract"
//         ));
//     };

//     let mut slashed_operators: HashMap<Address, HashSet<U256>> = HashMap::new();
//     for log in slash_logs {
//         let log_data = decode(
//             &vec![ParamType::Uint(256), ParamType::Uint(48)],
//             &log.data.to_vec(),
//         )
//         .context("Failed to decode symbiotic slash event data")?;

//         let Some(timestamp) = log_data[1].clone().into_uint() else {
//             return Err(anyhow!("Failed to parse timestamp for a slash event"));
//         };

//         if timestamp < U256::from(last_capture_timestamp)
//             || timestamp > U256::from(capture_timestamp)
//         {
//             continue;
//         }

//         let Some(operator) = log.topics[2].into_token().into_address() else {
//             return Err(anyhow!(
//                 "Failed to parse operator address for a slash event"
//             ));
//         };

//         slashed_operators
//             .entry(operator)
//             .or_insert_with(HashSet::new)
//             .extend(vec![timestamp]);
//     }

//     if slashed_operators.is_empty() {
//         return Err(anyhow!("No slash data found for any operator"));
//     }

//     let mut slash_proposed_filter = Filter::new()
//         .address(app_state.kalypso_middleware_addr)
//         .topic0(H256::from(keccak256(
//             "SlashProposed(uint256,address,address,uint256,uint256,address)",
//         )))
//         .topic2(H256::from(vault))
//         .topic3(slashed_operators.keys().cloned().collect::<Vec<Address>>())
//         .from_block(approximate_from_block);

//     if to_block_number.is_some() {
//         slash_proposed_filter = slash_proposed_filter.to_block(to_block_number.unwrap());
//     }

//     let Some(slash_proposed_logs) = get_logs(
//         &app_state.http_rpc_urls,
//         rpc_api_keys,
//         slash_proposed_filter,
//     )
//     .await
//     else {
//         return Err(anyhow!(
//             "Failed to fetch logs for slashing from middleware contract"
//         ));
//     };

//     let mut jobs_slashed: Vec<JobSlashed> = Vec::new();
//     for log in slash_proposed_logs {
//         let log_data = decode(
//             &vec![
//                 ParamType::Uint(256),
//                 ParamType::Uint(256),
//                 ParamType::Address,
//             ],
//             &log.data.to_vec(),
//         )
//         .context("Failed to decode middleware slash proposed event data")?;

//         let Some(timestamp) = log_data[1].clone().into_uint() else {
//             return Err(anyhow!(
//                 "Failed to parse timestamp for a slash proposed event"
//             ));
//         };

//         let Some(job_id) = log.topics[1].into_token().into_uint() else {
//             return Err(anyhow!("Failed to parse job ID for a slash proposed event"));
//         };
//         let Some(operator) = log.topics[3].into_token().into_address() else {
//             return Err(anyhow!(
//                 "Failed to parse operator address for a slash proposed event"
//             ));
//         };

//         if slashed_operators.contains_key(&operator)
//             && slashed_operators
//                 .get(&operator)
//                 .unwrap()
//                 .contains(&timestamp)
//         {
//             let Some(reward_address) = log_data[2].clone().into_address() else {
//                 return Err(anyhow!(
//                     "Failed to parse reward address for a slash proposed event"
//                 ));
//             };

//             jobs_slashed.push(JobSlashed {
//                 job_id: job_id,
//                 operator: operator,
//                 reward_address: reward_address,
//             });
//         }
//     }

//     Ok(jobs_slashed)
// }

// Get the stake amount in the provided vault of the given operator index in the operator registry
async fn get_stake_amount(
    operator_ind: U256,
    vault: H160,
    operator_registry: H160,
    operator_vault_opt_in_service: H160,
    operator_network_opt_in_service: H160,
    delegator: H160,
    rpc_block_map: HashMap<String, (u64, u64)>,
    app_state: Data<AppState>,
) -> Result<(H160, U256)> {
    // Fetch the operator using the index from the operator registry contract through the RPCs
    let Some(operator_address_encoded) = call_txn_with_rpcs(
        rpc_block_map.clone(),
        app_state.chain_id,
        operator_registry.clone(),
        &app_state.registry_abi,
        ViewTxnData::Entity(operator_ind),
    )
    .await
    else {
        return Err(anyhow!(
            "Failed to fetch the operator entity address for index {:?}",
            operator_ind
        ));
    };
    // Decode the address from the RPC responses
    let Some(operator) = decode(&[ParamType::Address], &operator_address_encoded)
        .context("Failed to decode operator entity address from rpc call response")?[0]
        .clone()
        .into_address()
    else {
        return Err(anyhow!(
            "Failed to decode the operator entity address for index {:?}",
            operator_ind
        ));
    };

    // Fetch whether the given operator is opted in the provided vault from the operator-vault-opt-in-service contract through the RPCs
    let Some(opted_in_vault_encoded) = call_txn_with_rpcs(
        rpc_block_map.clone(),
        app_state.chain_id,
        operator_vault_opt_in_service.clone(),
        &app_state.opt_in_service_abi,
        ViewTxnData::IsOptedIn(operator.clone(), vault.clone()),
    )
    .await
    else {
        return Err(anyhow!(
            "Failed to fetch is-operator-opted-in-vault for ({:?},{:?})",
            operator,
            vault
        ));
    };
    // Decode the boolean from the RPC response
    let Some(opted_in_vault) = decode(&[ParamType::Bool], &opted_in_vault_encoded)
        .context("Failed to decode is-operator-opted-in-vault from rpc call response")?[0]
        .clone()
        .into_bool()
    else {
        return Err(anyhow!(
            "Failed to decode is-operator-opted-in-vault for ({:?},{:?})",
            operator,
            vault
        ));
    };

    // Return zero values if the operator is not opted in the vault
    if !opted_in_vault {
        return Ok((H160::zero(), U256::zero()));
    }

    // Fetch whether the given operator is opted in the kalypso subnetwork from the operator-network-opt-in-service contract through the RPCs
    let Some(opted_in_network_encoded) = call_txn_with_rpcs(
        rpc_block_map.clone(),
        app_state.chain_id,
        operator_network_opt_in_service.clone(),
        &app_state.opt_in_service_abi,
        ViewTxnData::IsOptedIn(
            operator.clone(),
            h256_to_address(app_state.kalypso_subnetwork),
        ),
    )
    .await
    else {
        return Err(anyhow!(
            "Failed to fetch is-operator-opted-in-network for operator {:?}",
            operator
        ));
    };
    // Decode the boolean from the RPC response
    let Some(opted_in_network) = decode(&[ParamType::Bool], &opted_in_network_encoded)
        .context("Failed to decode is-operator-opted-in-network from rpc call response")?[0]
        .clone()
        .into_bool()
    else {
        return Err(anyhow!(
            "Failed to decode is-operator-opted-in-network for operator {:?}",
            operator
        ));
    };

    // Return zero values if the operator is not opted in the kalypso subnetwork
    if !opted_in_network {
        return Ok((H160::zero(), U256::zero()));
    }

    // Fetch the operator stake in the provided symbiotic vault from the delegator contract through the RPCs
    let Some(stake_amount_encoded) = call_txn_with_rpcs(
        rpc_block_map.clone(),
        app_state.chain_id,
        delegator.clone(),
        &app_state.base_delegator_abi,
        ViewTxnData::StakeAt(app_state.kalypso_subnetwork, operator.clone(), 0),
    )
    .await
    else {
        return Err(anyhow!(
            "Failed to fetch the stake amount for operator {:?}",
            operator
        ));
    };
    // Decode the amount from the RPC response
    let Some(stake_amount) = decode(&[ParamType::Uint(256)], &stake_amount_encoded)
        .context("Failed to decode the stake amount from rpc call response")?[0]
        .clone()
        .into_uint()
    else {
        return Err(anyhow!(
            "Failed to decode the stake amount for operator {:?}",
            operator
        ));
    };

    // Fetch the operator delegate from the kalypso middleware contract through the RPCs
    let Some(operator_delegate_encoded) = call_txn_with_rpcs(
        rpc_block_map.clone(),
        app_state.chain_id,
        app_state.kalypso_middleware_addr.clone(),
        &app_state.kalypso_middleware_abi,
        ViewTxnData::GetDelegate(operator),
    )
    .await
    else {
        return Err(anyhow!(
            "Failed to fetch the delegate address for operator {:?}",
            operator
        ));
    };
    // Decode the address from the RPC responses
    let Some(operator_delegate) = decode(&[ParamType::Address], &operator_delegate_encoded)
        .context("Failed to decode operator delegate address from rpc call response")?[0]
        .clone()
        .into_address()
    else {
        return Err(anyhow!(
            "Failed to decode the operator {:?} delegate address",
            operator
        ));
    };

    return Ok((operator_delegate, stake_amount));
}

// Method returning the state read call response for a smart contract using the configured RPCs
async fn call_txn_with_rpcs(
    rpc_block_map: HashMap<String, (u64, u64)>,
    chain_id: u64,
    contract_addr: H160,
    contract_abi: &Abi,
    view_txn_data: ViewTxnData,
) -> Option<Bytes> {
    // Generate the transaction object using the contract address, ABI and method data
    let txn = generate_txn(contract_addr, contract_abi, view_txn_data.clone());
    let Ok(mut txn) = txn else {
        eprintln!(
            "Failed to generate {} transaction: {:?}",
            view_txn_data.as_str(),
            txn.unwrap_err()
        );
        return None;
    };
    let txn: Arc<TypedTransaction> = txn.set_chain_id(chain_id).to_owned().into();

    // Create a mpsc channel
    let (tx, mut rx) = mpsc::channel::<Bytes>(10);

    // Call the transaction from each RPC in the mapping
    for (rpc_url, (block_num, timestamp)) in rpc_block_map {
        let tx_clone = tx.clone();
        let mut txn_clone = Arc::clone(&txn);

        // Update the timestamp for calling the 'stake' method in the symbiotic delegator contract according to the latest/provided RPC block
        if let ViewTxnData::StakeAt(subnetwork, operator, _) = view_txn_data {
            txn_clone = generate_txn(
                contract_addr,
                contract_abi,
                ViewTxnData::StakeAt(subnetwork, operator, timestamp),
            )
            .unwrap()
            .set_chain_id(chain_id)
            .to_owned()
            .into();
        }

        tokio::spawn(async move {
            call_txn_with_retries(&rpc_url, txn_clone, block_num, tx_clone).await;
        });
    }

    drop(tx);

    // Gather the RPC responses for the given transaction concurrently
    let mut txn_results = Vec::new();
    while let Some(result) = rx.recv().await {
        txn_results.push(result);
    }

    // Revert if responses less than the minimum required for validation
    if txn_results.len() < MIN_NUMBER_OF_RPC_RESPONSES {
        eprintln!(
            "Failed to get enough number of responses from rpcs for {} transaction",
            view_txn_data.as_str()
        );
        return None;
    }

    // Check whether all the RPC responses match
    let response = txn_results.pop().unwrap();
    while txn_results.len() > 0 {
        if response != txn_results.pop().unwrap() {
            eprintln!(
                "Mismatch in rpc responses for {} transaction",
                view_txn_data.as_str()
            );
            return None;
        }
    }

    return Some(response);
}

// Method calling a read transaction from a RPC with retries
async fn call_txn_with_retries(
    http_rpc_url: &String,
    txn: Arc<TypedTransaction>,
    block_num: u64,
    tx: Sender<Bytes>,
) {
    // Initialize the RPC Client from the given URL
    let http_rpc_client = Provider::<Http>::try_from(http_rpc_url);
    let Ok(http_rpc_client) = http_rpc_client else {
        eprintln!(
            "Failed to initialize http rpc {} client: {:?}",
            http_rpc_url,
            http_rpc_client.unwrap_err()
        );
        return;
    };

    // Call the transaction with the provided block number from the mapping
    let txn_result = Retry::spawn(
        ExponentialBackoff::from_millis(5).map(jitter).take(3),
        || async { http_rpc_client.call(&txn, Some(block_num.into())).await },
    )
    .await;
    let Ok(txn_result) = txn_result else {
        eprintln!(
            "Failed to retrieve txn {:?} response from http rpc {} client: {:?}",
            txn,
            http_rpc_url,
            txn_result.unwrap_err()
        );
        return;
    };

    // Send the transaction response from the RPC to the response receiver channel
    if let Err(err) = tx.send(txn_result).await {
        eprintln!(
            "Failed to send rpc {} response to the receiver channel: {:?}",
            http_rpc_url, err
        );
        return;
    }
}

// Get the block number (latest, if not provided) and its timestamp for a given RPC
async fn get_block_metadata(
    http_rpc_url: &String,
    block_number: Option<u64>,
) -> Option<(u64, u64)> {
    // Initialize the RPC Client from the given URL
    let http_rpc_client = Provider::<Http>::try_from(http_rpc_url);
    let Ok(http_rpc_client) = http_rpc_client else {
        eprintln!(
            "Failed to initialize http rpc {} client: {:?}",
            http_rpc_url,
            http_rpc_client.unwrap_err()
        );
        return None;
    };

    // Call the get block data transaction from the given RPC (latest if nothing provided)
    let block = Retry::spawn(
        ExponentialBackoff::from_millis(5).map(jitter).take(3),
        || async {
            if block_number.is_none() {
                http_rpc_client.get_block(BlockNumber::Latest).await
            } else {
                http_rpc_client
                    .get_block(block_number.clone().unwrap())
                    .await
            }
        },
    )
    .await;
    let Ok(Some(block)) = block else {
        eprintln!(
            "Failed to retrieve block data at {:?} from http rpc {} client: {:?}",
            block_number.clone(),
            http_rpc_url,
            block.unwrap_err()
        );
        return None;
    };

    let mut block_num = block_number;

    if block_num.is_none() {
        block_num = block.number.map(|num| num.as_u64());
    }

    // Revert if not abe to find the latest block number
    if block_num.is_none() {
        eprintln!(
            "Failed to retrieve latest block number from http rpc {} client response",
            http_rpc_url
        );
        return None;
    }

    return Some((block_num.unwrap(), block.timestamp.as_u64()));
}

// // Fetch the logs using the filter
// async fn get_logs(
//     http_rpc_urls: &Vec<String>,
//     rpc_api_keys: &Vec<String>,
//     filter: Filter,
// ) -> Option<Vec<Log>> {
//     for rpc_url in http_rpc_urls.iter() {
//         for api_key in rpc_api_keys.iter() {
//             let http_rpc_client = Provider::<Http>::try_from(format!("{}/{}", rpc_url, api_key));
//             let Ok(http_rpc_client) = http_rpc_client else {
//                 eprintln!(
//                     "Failed to initialize http rpc client: {:?}",
//                     http_rpc_client.unwrap_err()
//                 );
//                 continue;
//             };

//             let logs = Retry::spawn(
//                 ExponentialBackoff::from_millis(5).map(jitter).take(3),
//                 || async { http_rpc_client.get_logs(&filter).await },
//             )
//             .await;
//             let Ok(logs) = logs else {
//                 eprintln!(
//                     "Failed to retrieve response from http rpc client: {:?}",
//                     logs.unwrap_err()
//                 );
//                 continue;
//             };

//             return Some(logs);
//         }
//     }

//     return None;
// }
