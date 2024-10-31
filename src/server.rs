use actix_web::web::{Data, Json};
use actix_web::{get, post, HttpResponse, Responder};
use serde_json::json;

use crate::contract_calls::{get_stakes_data_for_vault, get_vaults_addresses};
use crate::signing::sign_vault_snapshots;
use crate::utils::{AppState, SignStakeRequest, VaultSnapshot};

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
    if sign_stake_request.rpc_api_keys.is_empty() {
        return HttpResponse::BadRequest()
            .body("At least 1 API Key (even empty) must be provided!\n");
    }

    if sign_stake_request.no_of_txs == 0 {
        return HttpResponse::BadRequest().body("Number of Txns must be greater than 0!\n");
    }

    let vaults_list = get_vaults_addresses(
        &sign_stake_request.rpc_api_keys,
        sign_stake_request.block_number,
        app_state.clone(),
    )
    .await;
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

    for vault in vaults_list.iter() {
        let snapshots = get_stakes_data_for_vault(
            vault,
            sign_stake_request.capture_timestamp,
            &sign_stake_request.rpc_api_keys,
            sign_stake_request.block_number,
            app_state.clone(),
        )
        .await;
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

    let signed_data = sign_vault_snapshots(
        vault_snapshots,
        sign_stake_request.no_of_txs,
        sign_stake_request.capture_timestamp,
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
        "capture_timestamp": sign_stake_request.capture_timestamp,
        "signed_data": signed_data,
    }))
}
