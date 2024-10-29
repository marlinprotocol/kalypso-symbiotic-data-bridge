use actix_web::web::{Data, Json};
use actix_web::{get, post, HttpResponse, Responder};
use ethers::abi::{encode, Token};
use ethers::utils::keccak256;
use k256::elliptic_curve::generic_array::sequence::Lengthen;
use serde_json::json;

use crate::contract_calls::{get_stakes_data_for_vault, get_vaults_addresses};
use crate::utils::{AppState, SignStakeRequest, SignedData, VaultSnapshot};

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
    let stakes_data_size = (vault_snapshot_tokens.len() + sign_stake_request.no_of_txs - 1)
        / sign_stake_request.no_of_txs;

    let mut signed_data: Vec<SignedData> = Vec::new();
    for tx_index in 0..sign_stake_request.no_of_txs {
        let tx_snapshot_tokens: Vec<Token> = vault_snapshot_tokens
            .drain(0..stakes_data_size.min(vault_snapshot_tokens.len()))
            .collect();
        let vault_snapshot_data = encode(&[Token::Array(tx_snapshot_tokens)]);

        let digest = keccak256(encode(&[
            Token::Uint(tx_index.into()),
            Token::Uint(sign_stake_request.no_of_txs.into()),
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

        signed_data.push(SignedData {
            stake_data: format!("0x{}", hex::encode(vault_snapshot_data)),
            signature: format!("0x{}", hex::encode(signature)),
        });
    }

    HttpResponse::Ok().json(json!({
        "no_of_txs": sign_stake_request.no_of_txs,
        "capture_timestamp": sign_stake_request.capture_timestamp,
        "signed_data": signed_data,
    }))
}
