use actix_web::web::{Data, Json};
use actix_web::{get, post, HttpResponse, Responder};

use crate::contract_calls::{get_stakes_data_for_vault, get_vaults_addresses};
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
        return HttpResponse::BadRequest().body("At least 1 API Key must be provided!\n");
    }

    if sign_stake_request.num_of_txns == 0 {
        return HttpResponse::BadRequest().body("Number of Txns must be greater than 0!\n");
    }

    let vaults_list = get_vaults_addresses(app_state.clone()).await;
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

    // TODO: Sign the data read

    HttpResponse::Ok().body("Job done")
}
