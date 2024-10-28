use actix_web::web::Data;
use anyhow::{anyhow, Context, Result};
use ethers::abi::{decode, ParamType};
use ethers::providers::{Http, Middleware, Provider};
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{Address, Bytes, H160, U256};
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use crate::utils::{
    generate_txn, h256_to_address, AppState, VaultSnapshot, ViewTxnMetadata, ViewTxnType,
};

pub async fn get_vaults_addresses(
    rpc_api_keys: &Vec<String>,
    block_number: Option<usize>,
    app_state: Data<AppState>,
) -> Result<Vec<H160>> {
    let get_vaults_txn = generate_txn(
        app_state.kalypso_middleware_addr,
        &app_state.kalypso_middleware_abi,
        &ViewTxnMetadata {
            txn_type: ViewTxnType::GetVaults,
            entity_data: None,
            is_opted_in_data: None,
            stake_at_data: None,
        },
    )
    .context("Failed to generate transaction to retrieve vault addresses")?
    .set_chain_id(app_state.mainnet_chain_id)
    .to_owned();

    let Some(vault_addresses_encoded) = call_tx_with_retries(
        &app_state.http_rpc_urls,
        rpc_api_keys,
        get_vaults_txn,
        block_number,
    )
    .await
    else {
        return Err(anyhow!("Failed to fetch the vault addresses token"));
    };
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

pub async fn get_stakes_data_for_vault(
    vault: &Address,
    capture_timestamp: usize,
    rpc_api_keys: &Vec<String>,
    block_number: Option<usize>,
    app_state: Data<AppState>,
) -> Result<Vec<VaultSnapshot>> {
    let collateral_txn = generate_txn(
        vault.clone(),
        &app_state.vault_abi,
        &ViewTxnMetadata {
            txn_type: ViewTxnType::Collateral,
            entity_data: None,
            is_opted_in_data: None,
            stake_at_data: None,
        },
    )
    .context("Failed to generate transaction for vault collateral")?
    .set_chain_id(app_state.mainnet_chain_id)
    .to_owned();

    let Some(stake_token_encoded) = call_tx_with_retries(
        &app_state.http_rpc_urls,
        rpc_api_keys,
        collateral_txn,
        block_number,
    )
    .await
    else {
        return Err(anyhow!("Failed to fetch the vault collateral token"));
    };
    let Some(stake_token) = decode(&[ParamType::Address], &stake_token_encoded)
        .context("Failed to decode stakeToken from rpc call response")?[0]
        .clone()
        .into_address()
    else {
        return Err(anyhow!("Failed to decode the stakeToken"));
    };

    let delegator_txn = generate_txn(
        vault.clone(),
        &app_state.vault_abi,
        &ViewTxnMetadata {
            txn_type: ViewTxnType::Delegator,
            entity_data: None,
            is_opted_in_data: None,
            stake_at_data: None,
        },
    )
    .context("Failed to generate transaction for vault delegator")?
    .set_chain_id(app_state.mainnet_chain_id)
    .to_owned();

    let Some(delegator_encoded) = call_tx_with_retries(
        &app_state.http_rpc_urls,
        rpc_api_keys,
        delegator_txn,
        block_number,
    )
    .await
    else {
        return Err(anyhow!("Failed to fetch the vault delegator address"));
    };
    let Some(delegator) = decode(&[ParamType::Address], &delegator_encoded)
        .context("Failed to decode delegator from rpc call response")?[0]
        .clone()
        .into_address()
    else {
        return Err(anyhow!("Failed to decode the delegator"));
    };

    let operator_vault_opt_in_txn = generate_txn(
        delegator.clone(),
        &app_state.base_delegator_abi,
        &ViewTxnMetadata {
            txn_type: ViewTxnType::OperatorVaultOptInService,
            entity_data: None,
            is_opted_in_data: None,
            stake_at_data: None,
        },
    )
    .context("Failed to generate transaction for operator vault opt in service")?
    .set_chain_id(app_state.mainnet_chain_id)
    .to_owned();

    let Some(operator_vault_opt_in_encoded) = call_tx_with_retries(
        &app_state.http_rpc_urls,
        rpc_api_keys,
        operator_vault_opt_in_txn,
        block_number,
    )
    .await
    else {
        return Err(anyhow!(
            "Failed to fetch the operator vault opt in service address"
        ));
    };
    let Some(operator_vault_opt_in_service) =
        decode(&[ParamType::Address], &operator_vault_opt_in_encoded)
            .context("Failed to decode operator vault opt in service from rpc call response")?[0]
            .clone()
            .into_address()
    else {
        return Err(anyhow!(
            "Failed to decode the operator vault opt in service address"
        ));
    };

    let operator_network_opt_in_txn = generate_txn(
        delegator.clone(),
        &app_state.base_delegator_abi,
        &ViewTxnMetadata {
            txn_type: ViewTxnType::OperatorNetworkOptInService,
            entity_data: None,
            is_opted_in_data: None,
            stake_at_data: None,
        },
    )
    .context("Failed to generate transaction for operator network opt in service")?
    .set_chain_id(app_state.mainnet_chain_id)
    .to_owned();

    let Some(operator_network_opt_in_encoded) = call_tx_with_retries(
        &app_state.http_rpc_urls,
        rpc_api_keys,
        operator_network_opt_in_txn,
        block_number,
    )
    .await
    else {
        return Err(anyhow!(
            "Failed to fetch the operator network opt in service address"
        ));
    };
    let Some(operator_network_opt_in_service) =
        decode(&[ParamType::Address], &operator_network_opt_in_encoded)
            .context("Failed to decode operator network opt in service from rpc call response")?[0]
            .clone()
            .into_address()
    else {
        return Err(anyhow!(
            "Failed to decode the operator network opt in service address"
        ));
    };

    let who_registry_txn = generate_txn(
        operator_vault_opt_in_service.clone(),
        &app_state.opt_in_service_abi,
        &ViewTxnMetadata {
            txn_type: ViewTxnType::WhoRegistry,
            entity_data: None,
            is_opted_in_data: None,
            stake_at_data: None,
        },
    )
    .context("Failed to generate transaction for operator registry")?
    .set_chain_id(app_state.mainnet_chain_id)
    .to_owned();

    let Some(operator_registry_encoded) = call_tx_with_retries(
        &app_state.http_rpc_urls,
        rpc_api_keys,
        who_registry_txn,
        block_number,
    )
    .await
    else {
        return Err(anyhow!("Failed to fetch the operator registry address"));
    };
    let Some(operator_registry) = decode(&[ParamType::Address], &operator_registry_encoded)
        .context("Failed to decode operator registry from rpc call response")?[0]
        .clone()
        .into_address()
    else {
        return Err(anyhow!("Failed to decode the operator registry address"));
    };

    let operator_entities_txn = generate_txn(
        operator_registry.clone(),
        &app_state.registry_abi,
        &ViewTxnMetadata {
            txn_type: ViewTxnType::TotalEntities,
            entity_data: None,
            is_opted_in_data: None,
            stake_at_data: None,
        },
    )
    .context("Failed to generate transaction for operator total entities")?
    .set_chain_id(app_state.mainnet_chain_id)
    .to_owned();

    let Some(operator_entities_encoded) = call_tx_with_retries(
        &app_state.http_rpc_urls,
        rpc_api_keys,
        operator_entities_txn,
        block_number,
    )
    .await
    else {
        return Err(anyhow!("Failed to fetch the operator total entities"));
    };
    let Some(operator_entities) = decode(&[ParamType::Uint(256)], &operator_entities_encoded)
        .context("Failed to decode operator total entities from rpc call response")?[0]
        .clone()
        .into_uint()
    else {
        return Err(anyhow!("Failed to decode the operator total entities"));
    };

    let mut operators_list: Vec<H160> = Vec::new();
    let mut operator_ind = U256::zero();
    while operator_ind < operator_entities {
        let operator_address_txn = generate_txn(
            operator_registry.clone(),
            &app_state.registry_abi,
            &ViewTxnMetadata {
                txn_type: ViewTxnType::Entity,
                entity_data: Some(operator_ind),
                is_opted_in_data: None,
                stake_at_data: None,
            },
        )
        .context("Failed to generate transaction for operator entity address")?
        .set_chain_id(app_state.mainnet_chain_id)
        .to_owned();

        let Some(operator_address_encoded) = call_tx_with_retries(
            &app_state.http_rpc_urls,
            rpc_api_keys,
            operator_address_txn,
            block_number,
        )
        .await
        else {
            return Err(anyhow!("Failed to fetch the operator entity address"));
        };
        let Some(operator_address) = decode(&[ParamType::Address], &operator_address_encoded)
            .context("Failed to decode operator entity address from rpc call response")?[0]
            .clone()
            .into_address()
        else {
            return Err(anyhow!("Failed to decode the operator entity address"));
        };

        operators_list.push(operator_address);
        operator_ind += U256::one();
    }

    let mut vault_snapshots: Vec<VaultSnapshot> = Vec::new();
    for operator in operators_list.iter() {
        let opted_in_vault_txn = generate_txn(
            operator_vault_opt_in_service.clone(),
            &app_state.opt_in_service_abi,
            &ViewTxnMetadata {
                txn_type: ViewTxnType::IsOptedIn,
                entity_data: None,
                is_opted_in_data: Some((operator.clone(), vault.clone())),
                stake_at_data: None,
            },
        )
        .context("Failed to generate transaction for is operator opted in vault")?
        .set_chain_id(app_state.mainnet_chain_id)
        .to_owned();

        let Some(opted_in_vault_encoded) = call_tx_with_retries(
            &app_state.http_rpc_urls,
            rpc_api_keys,
            opted_in_vault_txn,
            block_number,
        )
        .await
        else {
            return Err(anyhow!("Failed to fetch is operator opted in vault"));
        };
        let Some(opted_in_vault) = decode(&[ParamType::Bool], &opted_in_vault_encoded)
            .context("Failed to decode is operator opted in vault from rpc call response")?[0]
            .clone()
            .into_bool()
        else {
            return Err(anyhow!("Failed to decode is operator opted in vault"));
        };

        if !opted_in_vault {
            continue;
        }

        let opted_in_network_txn = generate_txn(
            operator_network_opt_in_service.clone(),
            &app_state.opt_in_service_abi,
            &ViewTxnMetadata {
                txn_type: ViewTxnType::IsOptedIn,
                entity_data: None,
                is_opted_in_data: Some((
                    operator.clone(),
                    h256_to_address(app_state.kalypso_subnetwork),
                )),
                stake_at_data: None,
            },
        )
        .context("Failed to generate transaction for is operator opted in network")?
        .set_chain_id(app_state.mainnet_chain_id)
        .to_owned();

        let Some(opted_in_network_encoded) = call_tx_with_retries(
            &app_state.http_rpc_urls,
            rpc_api_keys,
            opted_in_network_txn,
            block_number,
        )
        .await
        else {
            return Err(anyhow!("Failed to fetch is operator opted in network"));
        };
        let Some(opted_in_network) = decode(&[ParamType::Bool], &opted_in_network_encoded)
            .context("Failed to decode is operator opted in network from rpc call response")?[0]
            .clone()
            .into_bool()
        else {
            return Err(anyhow!("Failed to decode is operator opted in network"));
        };

        if !opted_in_network {
            continue;
        }

        let stake_at_txn = generate_txn(
            delegator.clone(),
            &app_state.base_delegator_abi,
            &ViewTxnMetadata {
                txn_type: ViewTxnType::StakeAt,
                entity_data: None,
                is_opted_in_data: None,
                stake_at_data: Some((
                    app_state.kalypso_subnetwork,
                    operator.clone(),
                    capture_timestamp,
                )),
            },
        )
        .context("Failed to generate transaction for stake at")?
        .set_chain_id(app_state.mainnet_chain_id)
        .to_owned();

        let Some(stake_amount_encoded) = call_tx_with_retries(
            &app_state.http_rpc_urls,
            rpc_api_keys,
            stake_at_txn,
            block_number,
        )
        .await
        else {
            return Err(anyhow!("Failed to fetch the stake amount"));
        };
        let Some(stake_amount) = decode(&[ParamType::Uint(256)], &stake_amount_encoded)
            .context("Failed to decode the stake amount from rpc call response")?[0]
            .clone()
            .into_uint()
        else {
            return Err(anyhow!("Failed to decode the stake amount"));
        };

        vault_snapshots.push(VaultSnapshot {
            operator: operator.clone(),
            vault: vault.clone(),
            stake_token: stake_token,
            stake_amount: stake_amount,
        });
    }

    Ok(vault_snapshots)
}

async fn call_tx_with_retries(
    http_rpc_urls: &Vec<String>,
    rpc_api_keys: &Vec<String>,
    txn: TypedTransaction,
    block_number: Option<usize>,
) -> Option<Bytes> {
    for rpc_url in http_rpc_urls.iter() {
        for api_key in rpc_api_keys.iter() {
            let http_rpc_client = Provider::<Http>::try_from(format!("{}{}", rpc_url, api_key));
            let Ok(http_rpc_client) = http_rpc_client else {
                eprintln!(
                    "Failed to initialize http rpc client: {:?}",
                    http_rpc_client.unwrap_err()
                );
                continue;
            };

            let txn_result = Retry::spawn(
                ExponentialBackoff::from_millis(5).map(jitter).take(3),
                || async {
                    http_rpc_client
                        .call(&txn, block_number.map(|num| (num as u64).into()))
                        .await
                },
            )
            .await;
            let Ok(txn_result) = txn_result else {
                eprintln!(
                    "Failed to retrieve response from http rpc client: {:?}",
                    txn_result.unwrap_err()
                );
                continue;
            };

            return Some(txn_result);
        }
    }

    return None;
}
