use anyhow::Result;
use ethers::abi::{encode, Token};
use ethers::utils::keccak256;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::generic_array::sequence::Lengthen;

use crate::utils::{SignedData, VaultSnapshot};

pub fn sign_vault_snapshots(
    vault_snapshots: Vec<VaultSnapshot>,
    no_of_txs: usize,
    capture_timestamp: usize,
    enclave_signer: &SigningKey,
) -> Result<Vec<SignedData>> {
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
    let stakes_batch_per_head = vault_snapshot_tokens.len() / no_of_txs;
    let stakes_batch_overhead = vault_snapshot_tokens.len() % no_of_txs;

    let mut signed_data: Vec<SignedData> = Vec::new();
    for tx_index in 0..no_of_txs {
        let mut batch_size = stakes_batch_per_head;
        if tx_index < stakes_batch_overhead {
            batch_size += 1;
        }

        let tx_snapshot_tokens: Vec<Token> = vault_snapshot_tokens
            .drain(0..batch_size.min(vault_snapshot_tokens.len()))
            .collect();
        let vault_snapshot_data = encode(&[Token::Array(tx_snapshot_tokens)]);

        let digest = keccak256(encode(&[
            Token::FixedBytes(keccak256("STAKE_SNAPSHOT_TYPE").to_vec()),
            Token::Uint(tx_index.into()),
            Token::Uint(no_of_txs.into()),
            Token::Uint(capture_timestamp.into()),
            Token::Bytes(vault_snapshot_data.clone()),
        ]));
        let prefix = format!("\x19Ethereum Signed Message:\n{}", digest.len());
        let prefixed_digest = keccak256([prefix.as_bytes(), &digest].concat());

        let (rs, v) = enclave_signer.sign_prehash_recoverable(&prefixed_digest)?;
        let signature = rs.to_bytes().append(27 + v.to_byte()).to_vec();

        signed_data.push(SignedData {
            stake_data: format!("0x{}", hex::encode(vault_snapshot_data)),
            signature: format!("0x{}", hex::encode(signature)),
        });
    }

    Ok(signed_data)
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use ethers::abi::{decode, ParamType};
    use ethers::types::H160;
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use k256::elliptic_curve::rand_core::OsRng;

    use super::*;

    #[test]
    fn test_signing_vault_snapshots_1() {
        test_signing_vault_snapshots(3, 2);
    }

    #[test]
    fn test_signing_vault_snapshots_2() {
        test_signing_vault_snapshots(6, 3);
    }

    #[test]
    fn test_signing_vault_snapshots_3() {
        test_signing_vault_snapshots(10, 6);
    }

    fn test_signing_vault_snapshots(num_snapshots: u64, no_of_txs: usize) {
        assert!(
            num_snapshots >= (no_of_txs as u64),
            "Number of snapshots less than number of Txns expected!"
        );

        let signer = SigningKey::random(&mut OsRng);
        let vault_snapshots: Vec<VaultSnapshot> = (0..num_snapshots)
            .into_iter()
            .map(|ind| generate_random_vault_snapshot(ind * 10))
            .collect();
        let capture_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let signed_data = sign_vault_snapshots(
            vault_snapshots.clone(),
            no_of_txs,
            capture_timestamp as usize,
            &signer,
        );
        assert!(signed_data.is_ok());

        let signed_data = signed_data.unwrap();
        assert_eq!(signed_data.len(), no_of_txs);

        let mut snapshot_ind = 0;
        for ind in 0..no_of_txs {
            let stake_data_bytes = hex::decode(&signed_data[ind].stake_data[2..]).unwrap();

            assert_eq!(
                recover_key(
                    ind,
                    no_of_txs,
                    capture_timestamp as usize,
                    stake_data_bytes.clone(),
                    signed_data[ind].signature.clone()
                ),
                signer.verifying_key().to_owned()
            );

            let stake_data_decoded = decode(
                &[ParamType::Array(Box::new(ParamType::Tuple(vec![
                    ParamType::Address,
                    ParamType::Address,
                    ParamType::Address,
                    ParamType::Uint(256),
                ])))],
                &stake_data_bytes,
            )
            .unwrap()[0]
                .clone()
                .into_array()
                .unwrap();

            assert!(!stake_data_decoded.is_empty());

            for token in 0..stake_data_decoded.len() {
                assert!(snapshot_ind < vault_snapshots.len());

                let snapshot_tuple = stake_data_decoded[token].clone().into_tuple().unwrap();

                assert_eq!(snapshot_tuple.len(), 4);
                assert_eq!(
                    snapshot_tuple[0].clone().into_address().unwrap(),
                    vault_snapshots[snapshot_ind].operator
                );
                assert_eq!(
                    snapshot_tuple[1].clone().into_address().unwrap(),
                    vault_snapshots[snapshot_ind].vault
                );
                assert_eq!(
                    snapshot_tuple[2].clone().into_address().unwrap(),
                    vault_snapshots[snapshot_ind].stake_token
                );
                assert_eq!(
                    snapshot_tuple[3].clone().into_uint().unwrap(),
                    vault_snapshots[snapshot_ind].stake_amount
                );

                snapshot_ind += 1;
            }
        }
    }

    fn generate_random_vault_snapshot(stake_amount: u64) -> VaultSnapshot {
        VaultSnapshot {
            operator: H160::random(),
            vault: H160::random(),
            stake_token: H160::random(),
            stake_amount: stake_amount.into(),
        }
    }

    fn recover_key(
        tx_index: usize,
        no_of_txs: usize,
        capture_timestamp: usize,
        stake_data: Vec<u8>,
        signature: String,
    ) -> VerifyingKey {
        let digest = keccak256(encode(&[
            Token::FixedBytes(keccak256("STAKE_SNAPSHOT_TYPE").to_vec()),
            Token::Uint(tx_index.into()),
            Token::Uint(no_of_txs.into()),
            Token::Uint(capture_timestamp.into()),
            Token::Bytes(stake_data),
        ]));
        let prefix = format!("\x19Ethereum Signed Message:\n{}", digest.len());
        let prefixed_digest = keccak256([prefix.as_bytes(), &digest].concat());

        let sign =
            Signature::from_slice(hex::decode(&signature[2..130]).unwrap().as_slice()).unwrap();
        let v = RecoveryId::try_from((hex::decode(&signature[130..]).unwrap()[0]) - 27).unwrap();
        let recovered_key = VerifyingKey::recover_from_prehash(&prefixed_digest, &sign, v).unwrap();

        recovered_key
    }
}
