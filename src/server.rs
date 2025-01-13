use std::collections::HashMap;

use actix_web::web::{Data, Json};
use actix_web::{get, post, HttpResponse, Responder};
use serde_json::json;

use crate::contract_calls::*;
use crate::signing::*;
use crate::utils::{
    AppState, JobSlashed, SignSlashRequest, SignStakeRequest, VaultSnapshot,
    MIN_NUMBER_OF_RPC_RESPONSES,
};

// Base route indicating server is up and running
#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok()
}

#[post("/sign-stake-data")]
// Endpoint exposed to read stakes data from symbiotic vaults and sign them
async fn read_and_sign_stakes(
    Json(sign_stake_request): Json<SignStakeRequest>,
    app_state: Data<AppState>,
) -> impl Responder {
    // Check whether API keys are provided corresponding to each RPC URL configured in the enclave
    if sign_stake_request.rpc_api_keys.len() != app_state.http_rpc_urls.len() {
        return HttpResponse::BadRequest().body(format!(
            "Require {} API keys corresponding to public, infura and alchemy RPCs!\n",
            app_state.http_rpc_urls.len()
        ));
    }

    if sign_stake_request.no_of_txs == 0 {
        return HttpResponse::BadRequest().body("Number of Txns must be greater than 0!\n");
    }

    // Get the mapping from RPC URLs to their corresponding blocks and timestamps (used while making state read calls)
    let rpc_block_map: HashMap<String, (u64, u64)> = get_block_number_and_timestamps(
        app_state.http_rpc_urls.clone(),
        sign_stake_request.rpc_api_keys.into(),
        sign_stake_request.block_number,
    )
    .await;
    // Check whether a minimum number of RPCs are available to generate and validate the response
    if rpc_block_map.len() < MIN_NUMBER_OF_RPC_RESPONSES {
        return HttpResponse::InternalServerError().body(format!(
            "Threshold {} number of RPCs not available!\n",
            MIN_NUMBER_OF_RPC_RESPONSES
        ));
    }

    // Get the lists of vaults associated with the kalypso subnetwork
    let vaults_list = get_vaults_addresses(rpc_block_map.clone(), app_state.clone()).await;
    let Ok(vaults_list) = vaults_list else {
        return HttpResponse::InternalServerError().body(format!(
            "Failed to fetch the vaults address list for reading stakes: {:?}\n",
            vaults_list.unwrap_err()
        ));
    };
    if vaults_list.is_empty() {
        return HttpResponse::BadRequest()
            .body("No vaults found associated with the kalypso network!\n");
    }

    let mut vault_snapshots: Vec<VaultSnapshot> = Vec::new();

    // Retrieve stakes data associated with each vault in the kalypso subnetwork
    for vault in vaults_list.iter() {
        let snapshots =
            get_stakes_data_for_vault(vault, rpc_block_map.clone(), app_state.clone()).await;
        let Ok(snapshots) = snapshots else {
            return HttpResponse::InternalServerError().body(format!(
                "Failed to retrieve stakes data for vault {:?} from the RPC: {:?}\n",
                vault,
                snapshots.unwrap_err()
            ));
        };

        vault_snapshots.extend(snapshots);
    }

    if vault_snapshots.len() < sign_stake_request.no_of_txs {
        return HttpResponse::BadRequest().body(format!(
            "Number of stakes found {} is less than the number of txns expected!\n",
            vault_snapshots.len()
        ));
    }

    // Calculate the capture timestamp to be used for signing and posting the data on the L2 contract
    let mut capture_timestamp = 0;
    let mut block_number = 0;
    for (num, timestamp) in rpc_block_map.values() {
        if timestamp >= &capture_timestamp {
            capture_timestamp = timestamp.clone();
            block_number = num.clone();
        }
    }

    // Get the signed data to be submitted on-chain
    let signed_data = sign_vault_snapshots(
        vault_snapshots,
        sign_stake_request.no_of_txs,
        capture_timestamp,
        &app_state.enclave_signer,
    );
    let Ok(signed_data) = signed_data else {
        return HttpResponse::InternalServerError().body(format!(
            "Failed to sign the stakes data message using enclave key: {:?}\n",
            signed_data.unwrap_err()
        ));
    };

    HttpResponse::Ok().json(json!({
        "no_of_txs": sign_stake_request.no_of_txs,
        "capture_timestamp": capture_timestamp,
        "block_number": block_number,
        "signed_data": signed_data,
    }))
}

#[post("/sign-slash-data")]
// Endpoint exposed to read slash data from symbiotic vaults and sign them
async fn read_and_sign_slashes(
    Json(sign_slash_request): Json<SignSlashRequest>,
    app_state: Data<AppState>,
) -> impl Responder {
    // Check whether API keys are provided corresponding to each RPC URL configured in the enclave
    if sign_slash_request.rpc_api_keys.len() != app_state.http_rpc_urls.len() {
        return HttpResponse::BadRequest().body(format!(
            "Require {} API keys corresponding to public, infura and alchemy RPCs!\n",
            app_state.http_rpc_urls.len()
        ));
    }

    if sign_slash_request.no_of_txs == 0 {
        return HttpResponse::BadRequest().body("Number of Txns must be greater than 0!\n");
    }

    // // Get the mapping from RPC URLs to their corresponding blocks and timestamps (used while making state read calls)
    // let rpc_block_map: HashMap<String, (u64, u64)> = get_block_number_and_timestamps(
    //     app_state.http_rpc_urls.clone(),
    //     sign_slash_request.rpc_api_keys.into(),
    //     sign_slash_request.to_block_number,
    // )
    // .await;
    // if rpc_block_map.len() < MIN_NUMBER_OF_RPC_RESPONSES {
    //     return HttpResponse::InternalServerError().body("Rpc Server Error!/n");
    // }

    // let vaults_list = get_vaults_addresses(
    //     sign_slash_request.rpc_api_keys.clone().into(),
    //     rpc_block_map.clone(),
    //     app_state.clone(),
    // )
    // .await;
    // let Ok(vaults_list) = vaults_list else {
    //     return HttpResponse::InternalServerError().body(format!(
    //         "Failed to fetch the vaults address list for reading slashes: {:?}\n",
    //         vaults_list.unwrap_err()
    //     ));
    // };

    let slash_results: Vec<JobSlashed> = Vec::new();

    // for vault in vaults_list.iter() {
    //     let snapshots = get_slash_data_for_vault(
    //         vault.to_owned(),
    //         sign_slash_request.capture_timestamp,
    //         sign_slash_request.last_capture_timestamp,
    //         &sign_slash_request.rpc_api_keys,
    //         sign_slash_request.from_block_number,
    //         sign_slash_request.to_block_number,
    //         app_state.clone(),
    //     )
    //     .await;
    //     let Ok(snapshots) = snapshots else {
    //         return HttpResponse::InternalServerError().body(format!(
    //             "Failed to retrieve slash data for vault {:?} from the RPC: {:?}\n",
    //             vault,
    //             snapshots.unwrap_err()
    //         ));
    //     };

    //     slash_results.extend(snapshots);
    // }

    // if slash_results.len() < sign_slash_request.no_of_txs {
    //     return HttpResponse::BadRequest().body(format!(
    //         "Number of slashes found {} is less than the number of txns expected!\n",
    //         slash_results.len()
    //     ));
    // }

    // // Calculate the capture timestamp to be used for signing and posting the data on the L2 contract
    // let mut capture_timestamp = 0;
    // for (_, timestamp) in rpc_block_map.values() {
    //     capture_timestamp = cmp::max(capture_timestamp, timestamp.clone());
    // }

    // Get the signed data to be submitted on-chain
    let signed_data = sign_slash_results(
        slash_results,
        sign_slash_request.no_of_txs,
        sign_slash_request.capture_timestamp,
        &app_state.enclave_signer,
    );
    let Ok(signed_data) = signed_data else {
        return HttpResponse::InternalServerError().body(format!(
            "Failed to sign the slash results message using enclave key: {:?}\n",
            signed_data.unwrap_err()
        ));
    };

    HttpResponse::Ok().json(json!({
        "no_of_txs": sign_slash_request.no_of_txs,
        "capture_timestamp": sign_slash_request.capture_timestamp,
        "signed_data": signed_data,
    }))
}
