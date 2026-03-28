use super::validation::{parse_network, validate_json};
use crate::error::Error;
use crate::handlers::ok_response;
use crate::proto::pb::Response as PbResponse;
use crate::router::HandlerContext;
use crate::wallet::manager::WalletManager;
use crate::wallet::types::{AddressType, WalletMetadata};
use base64::Engine;
use bdk_wallet::SignOptions;
use bitcoin::psbt::Psbt;
use serde::Deserialize;
use tracing::{error, info};

#[derive(Deserialize)]
struct SignRequest {
    psbt: String,
    network: String,
}

fn parse_sign_request(
    data: &serde_json::Value,
    missing_psbt_message: &'static str,
) -> Result<SignRequest, Error> {
    if data.get("psbt").is_none() {
        return Err(Error::InvalidRequest(missing_psbt_message.to_string()));
    }
    if data.get("network").is_none() {
        return Err(Error::InvalidRequest("missing 'network' parameter".to_string()));
    }

    validate_json(data)
}

fn validate_output_networks(psbt: &Psbt, wallet_network: bitcoin::Network) -> Result<(), Error> {
    for (index, output) in psbt.unsigned_tx.output.iter().enumerate() {
        match bitcoin::Address::from_script(&output.script_pubkey, wallet_network) {
            Ok(_) => {}
            Err(bitcoin::address::FromScriptError::UnrecognizedScript) => {}
            Err(err) => {
                return Err(Error::InvalidRequest(format!(
                    "output {index} has incompatible address-like script for wallet network {}: {err}",
                    wallet_network
                )));
            }
        }
    }

    Ok(())
}

fn script_matches_address_type(
    script_pubkey: &bitcoin::Script,
    input: &bitcoin::psbt::Input,
    address_type: AddressType,
) -> Result<bool, Error> {
    match address_type {
        AddressType::Legacy => Ok(script_pubkey.is_p2pkh()),
        AddressType::NestedSegwit => {
            if !script_pubkey.is_p2sh() {
                return Ok(false);
            }

            let redeem_script = input.redeem_script.as_ref().ok_or_else(|| {
                Error::InvalidRequest(
                    "nested-segwit input missing redeem script context".to_string(),
                )
            })?;

            Ok(redeem_script.is_p2wpkh())
        }
        AddressType::NativeSegwit => Ok(script_pubkey.is_p2wpkh()),
        AddressType::Taproot => Ok(script_pubkey.is_p2tr()),
    }
}

fn validate_signing_policy(
    psbt: &Psbt,
    metadata: &WalletMetadata,
    declared_network: bitcoin::Network,
) -> Result<(), Error> {
    if declared_network != metadata.network {
        return Err(Error::InvalidRequest(format!(
            "declared network {} does not match wallet network {}",
            declared_network, metadata.network
        )));
    }

    validate_output_networks(psbt, metadata.network)?;

    for (index, input) in psbt.inputs.iter().enumerate() {
        let previous_output = psbt.unsigned_tx.input[index].previous_output;
        let script_pubkey = if let Some(witness_utxo) = &input.witness_utxo {
            &witness_utxo.script_pubkey
        } else if let Some(non_witness_utxo) = &input.non_witness_utxo {
            let output = non_witness_utxo
                .output
                .get(previous_output.vout as usize)
                .ok_or_else(|| {
                    Error::InvalidRequest(format!(
                        "input {index} missing UTXO script context for vout {}",
                        previous_output.vout
                    ))
                })?;
            &output.script_pubkey
        } else {
            return Err(Error::InvalidRequest(format!(
                "input {index} missing UTXO script context"
            )));
        };

        if !script_matches_address_type(script_pubkey.as_script(), input, metadata.address_type)? {
            return Err(Error::InvalidRequest(format!(
                "input {index} uses unsupported script template for wallet policy"
            )));
        }
    }

    Ok(())
}

/// POST /wallets/:name/sign - Sign a PSBT.
///
/// Request data:
/// - `psbt`: Base64-encoded PSBT string
///
/// Returns the signed PSBT (base64) and whether signing is complete.
pub async fn sign_psbt(ctx: HandlerContext) -> Result<PbResponse, Error> {
    let name = ctx
        .params
        .get("name")
        .ok_or_else(|| Error::InvalidRequest("missing wallet name".to_string()))?;

    let request = parse_sign_request(&ctx.data, "missing 'psbt' parameter")?;
    let psbt_b64 = request.psbt;
    let declared_network = parse_network(&request.network)?;

    info!(wallet = %name, "Signing PSBT");

    // Decode PSBT
    let psbt_bytes = base64::engine::general_purpose::STANDARD
        .decode(&psbt_b64)
        .map_err(|e| {
            error!(wallet = %name, error = %e, "Invalid PSBT base64 for signing");
            Error::InvalidPsbt(format!("invalid base64: {e}"))
        })?;

    let mut psbt = Psbt::deserialize(&psbt_bytes).map_err(|e| {
        error!(wallet = %name, error = %e, "Invalid PSBT for signing");
        Error::InvalidPsbt(format!("invalid PSBT: {e}"))
    })?;

    // Load wallet with private keys
    let (wallet, metadata) = WalletManager::load_bdk_wallet(ctx.storage.clone(), name).await?;

    validate_signing_policy(&psbt, &metadata, declared_network)?;

    // Sign
    let finalized = wallet
        .sign(&mut psbt, SignOptions::default())
        .map_err(|e| Error::SigningError(e.to_string()))?;

    // Encode result
    let signed_psbt = base64::engine::general_purpose::STANDARD.encode(psbt.serialize());

    Ok(ok_response(serde_json::json!({
        "psbt": signed_psbt,
        "complete": finalized,
    })))
}

/// POST /wallets/:name/sign-raw - Sign a raw transaction.
///
/// This creates a PSBT from the provided raw transaction, signs it,
/// finalizes it, and returns the signed raw transaction.
///
/// Request data:
/// - `psbt`: Base64-encoded PSBT (preferred)
/// - OR `tx`: Hex-encoded raw transaction (will be converted to PSBT)
pub async fn sign_raw(ctx: HandlerContext) -> Result<PbResponse, Error> {
    let name = ctx
        .params
        .get("name")
        .ok_or_else(|| Error::InvalidRequest("missing wallet name".to_string()))?;

    // We require a PSBT input even for "raw" signing, as constructing a valid
    // PSBT from just a raw transaction requires UTXO data
    let request = parse_sign_request(
        &ctx.data,
        "missing 'psbt' parameter - provide a PSBT for signing",
    )?;
    let psbt_b64 = request.psbt;
    let declared_network = parse_network(&request.network)?;

    info!(wallet = %name, "Signing raw transaction via PSBT");

    let psbt_bytes = base64::engine::general_purpose::STANDARD
        .decode(&psbt_b64)
        .map_err(|e| {
            error!(wallet = %name, error = %e, "Invalid PSBT base64 for raw signing");
            Error::InvalidPsbt(format!("invalid base64: {e}"))
        })?;

    let mut psbt = Psbt::deserialize(&psbt_bytes).map_err(|e| {
        error!(wallet = %name, error = %e, "Invalid PSBT for raw signing");
        Error::InvalidPsbt(format!("invalid PSBT: {e}"))
    })?;

    let (wallet, metadata) = WalletManager::load_bdk_wallet(ctx.storage.clone(), name).await?;

    validate_signing_policy(&psbt, &metadata, declared_network)?;

    let finalized = wallet
        .sign(&mut psbt, SignOptions::default())
        .map_err(|e| Error::SigningError(e.to_string()))?;

    if finalized {
        // Extract the final transaction
        let tx = psbt.extract_tx().map_err(|e| {
            Error::SigningError(format!("failed to extract signed transaction: {e}"))
        })?;
        let tx_hex = hex::encode(bitcoin::consensus::serialize(&tx));
        let txid = tx.compute_txid();

        Ok(ok_response(serde_json::json!({
            "signed_tx": tx_hex,
            "txid": txid.to_string(),
            "complete": true,
        })))
    } else {
        let signed_psbt = base64::engine::general_purpose::STANDARD.encode(psbt.serialize());
        Ok(ok_response(serde_json::json!({
            "psbt": signed_psbt,
            "complete": false,
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;
    use crate::wallet::types::{AddressType, WalletMetadata};
    use async_trait::async_trait;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid};
    use std::collections::HashMap;
    use std::sync::Arc;

    struct NoopStorage;

    #[async_trait]
    impl Storage for NoopStorage {
        async fn get(&self, _key: &str) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
            Ok(None)
        }

        async fn put(&self, _key: &str, _value: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }

        async fn delete(&self, _key: &str) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }

        async fn list(&self, _prefix: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
            Ok(vec![])
        }

        async fn put_sealed(
            &self,
            _key: &str,
            _value: Vec<u8>,
        ) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }
    }

    fn test_context(data: serde_json::Value) -> HandlerContext {
        HandlerContext {
            params: HashMap::from([(String::from("name"), String::from("test-wallet"))]),
            data,
            storage: Arc::new(NoopStorage),
        }
    }

    fn test_metadata(address_type: AddressType) -> WalletMetadata {
        WalletMetadata {
            name: "test-wallet".to_string(),
            network: Network::Testnet,
            address_type,
            created_at: 0,
            external_descriptor_public: "wpkh(tpub...)".to_string(),
            internal_descriptor_public: "wpkh(tpub...)".to_string(),
            next_external_index: 0,
            next_internal_index: 0,
        }
    }

    fn psbt_with_witness_utxo(script_pubkey: ScriptBuf) -> Psbt {
        let unsigned_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::all_zeros(), 0),
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(5_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("PSBT creation must succeed");
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey,
        });
        psbt
    }

    fn psbt_with_output(script_pubkey: ScriptBuf) -> Psbt {
        let unsigned_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::all_zeros(), 0),
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(5_000),
                script_pubkey,
            }],
        };

        Psbt::from_unsigned_tx(unsigned_tx).expect("PSBT creation must succeed")
    }

    fn malformed_witness_program_script() -> ScriptBuf {
        ScriptBuf::from_bytes(vec![0x00, 0x02, 0x01, 0x02])
    }

    #[test]
    fn test_sign_request_deserializes() {
        let request: SignRequest = serde_json::from_value(serde_json::json!({
            "psbt": "cHNidP8BAAoCAAAAAQ==",
            "network": "testnet"
        }))
        .expect("request should deserialize");

        assert_eq!(request.psbt, "cHNidP8BAAoCAAAAAQ==");
        assert_eq!(request.network, "testnet");
    }

    #[tokio::test]
    async fn test_sign_psbt_missing_psbt_returns_specific_error() {
        let err = sign_psbt(test_context(serde_json::json!({ "network": "testnet" })))
            .await
            .expect_err("missing psbt should fail");

        assert!(matches!(
            err,
            Error::InvalidRequest(message) if message == "missing 'psbt' parameter"
        ));
    }

    #[tokio::test]
    async fn test_sign_psbt_missing_network_returns_specific_error() {
        let err = sign_psbt(test_context(serde_json::json!({ "psbt": "cHNidP8BAAoCAAAAAQ==" })))
            .await
            .expect_err("missing network should fail");

        assert!(matches!(
            err,
            Error::InvalidRequest(message) if message == "missing 'network' parameter"
        ));
    }

    #[tokio::test]
    async fn test_sign_raw_missing_psbt_returns_specific_error() {
        let err = sign_raw(test_context(serde_json::json!({ "network": "testnet" })))
            .await
            .expect_err("missing psbt should fail");

        assert!(matches!(
            err,
            Error::InvalidRequest(message)
                if message == "missing 'psbt' parameter - provide a PSBT for signing"
        ));
    }

    #[test]
    fn test_validate_signing_policy_accepts_matching_native_segwit_script() {
        let psbt = psbt_with_witness_utxo(ScriptBuf::new_p2wpkh(
            &bitcoin::WPubkeyHash::all_zeros(),
        ));

        let result = validate_signing_policy(&psbt, &test_metadata(AddressType::NativeSegwit), Network::Testnet);

        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_signing_policy_rejects_unsupported_script_template() {
        let psbt = psbt_with_witness_utxo(ScriptBuf::new_p2tr(
            &bitcoin::secp256k1::Secp256k1::verification_only(),
            bitcoin::XOnlyPublicKey::from_slice(&[2; 32]).expect("xonly key must parse"),
            None,
        ));

        let err = validate_signing_policy(&psbt, &test_metadata(AddressType::NativeSegwit), Network::Testnet)
            .expect_err("unsupported script template must fail");

        assert!(matches!(
            err,
            Error::InvalidRequest(message) if message.contains("unsupported script template")
        ));
    }

    #[test]
    fn test_validate_signing_policy_rejects_malformed_address_like_output() {
        let psbt = psbt_with_output(malformed_witness_program_script());

        let err = validate_signing_policy(
            &psbt,
            &test_metadata(AddressType::NativeSegwit),
            Network::Testnet,
        )
        .expect_err("malformed address-like outputs must fail closed");

        assert!(matches!(
            err,
            Error::InvalidRequest(message) if message.contains("output 0") && message.contains("address-like script")
        ));
    }

    #[test]
    fn test_validate_signing_policy_rejects_nested_segwit_without_redeem_script() {
        let script_hash = bitcoin::ScriptHash::from_byte_array([3; 20]);
        let psbt = psbt_with_witness_utxo(ScriptBuf::new_p2sh(&script_hash));

        let err = validate_signing_policy(
            &psbt,
            &test_metadata(AddressType::NestedSegwit),
            Network::Testnet,
        )
        .expect_err("ambiguous nested segwit inputs must fail closed");

        assert!(matches!(
            err,
            Error::InvalidRequest(message) if message.contains("nested-segwit") && message.contains("redeem")
        ));
    }

    #[test]
    fn test_validate_signing_policy_accepts_nested_segwit_with_matching_redeem_script() {
        let script_hash = bitcoin::ScriptHash::hash(ScriptBuf::new_p2wpkh(
            &bitcoin::WPubkeyHash::all_zeros(),
        )
        .as_bytes());
        let mut psbt = psbt_with_witness_utxo(ScriptBuf::new_p2sh(&script_hash));
        psbt.inputs[0].redeem_script = Some(ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::all_zeros()));

        let result = validate_signing_policy(
            &psbt,
            &test_metadata(AddressType::NestedSegwit),
            Network::Testnet,
        );

        assert!(result.is_ok());
    }
}
