use actix_web::web::{Bytes, Data, Json};
use actix_web::{get, post, HttpResponse, Responder};
use ethers::abi::{encode, Token};
use ethers::utils::keccak256;
use k256::elliptic_curve::generic_array::sequence::Lengthen;
use serde_json::json;

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

    if sign_stake_request.stakes_txn_size == 0 {
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

    let mut vault_snapshot_tokens: Vec<Token> = vault_snapshots
        .into_iter()
        .map(|snapshot| {
            Token::Tuple(vec![
                Token::Address(snapshot.operator),
                Token::Address(snapshot.vault),
                Token::Address(snapshot.stake_token),
                Token::Uint(snapshot.stake_amount),
            ])
        })
        .collect();
    let num_of_txns = (vault_snapshot_tokens.len() + sign_stake_request.stakes_txn_size - 1)
        / sign_stake_request.stakes_txn_size;

    let mut signed_data: Vec<(Bytes, Bytes)> = Vec::new();
    for tx_index in 0..num_of_txns {
        let tx_snapshot_tokens: Vec<Token> = vault_snapshot_tokens
            .drain(
                0..sign_stake_request
                    .stakes_txn_size
                    .min(vault_snapshot_tokens.len()),
            )
            .collect();
        let vault_snapshot_data = encode(&[Token::Array(tx_snapshot_tokens)]);

        let digest = keccak256(encode(&[
            Token::Uint(tx_index.into()),
            Token::Uint(num_of_txns.into()),
            Token::Uint(sign_stake_request.capture_timestamp.into()),
            Token::Bytes(vault_snapshot_data.clone()),
        ]));
        let sig = app_state.enclave_signer.sign_prehash_recoverable(&digest);
        let Ok((rs, v)) = sig else {
            return HttpResponse::InternalServerError().body(format!(
                "Failed to sign the stakes data message using enclave key: {:?}\n",
                sig.unwrap_err()
            ));
        };
        let signature = rs.to_bytes().append(27 + v.to_byte()).to_vec();

        signed_data.push((vault_snapshot_data.into(), signature.into()));
    }

    HttpResponse::Ok().json(json!({
        "noOfTxs": num_of_txns,
        "captureTimestamp": sign_stake_request.capture_timestamp,
        "signedData": signed_data,
    }))
}
