use super::validation::validate_json;
use crate::error::Error;
use crate::handlers::ok_response;
use crate::proto::pb::Response as PbResponse;
use crate::router::HandlerContext;
use crate::wallet::manager::WalletManager;
use base64::Engine;
use bdk_wallet::SignOptions;
use bitcoin::psbt::Psbt;
use serde::Deserialize;
use tracing::{error, info};

#[derive(Deserialize)]
struct SignRequest {
    psbt: String,
}

fn parse_sign_request(
    data: &serde_json::Value,
    missing_psbt_message: &'static str,
) -> Result<SignRequest, Error> {
    if data.get("psbt").is_none() {
        return Err(Error::InvalidRequest(missing_psbt_message.to_string()));
    }

    validate_json(data)
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
    let (wallet, _metadata) = WalletManager::load_bdk_wallet(ctx.storage.clone(), name).await?;

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

    let (wallet, _metadata) = WalletManager::load_bdk_wallet(ctx.storage.clone(), name).await?;

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
    use async_trait::async_trait;
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

    #[test]
    fn test_sign_request_deserializes() {
        let request: SignRequest = serde_json::from_value(serde_json::json!({
            "psbt": "cHNidP8BAAoCAAAAAQ=="
        }))
        .expect("request should deserialize");

        assert_eq!(request.psbt, "cHNidP8BAAoCAAAAAQ==");
    }

    #[tokio::test]
    async fn test_sign_psbt_missing_psbt_returns_specific_error() {
        let err = sign_psbt(test_context(serde_json::json!({})))
            .await
            .expect_err("missing psbt should fail");

        assert!(matches!(
            err,
            Error::InvalidRequest(message) if message == "missing 'psbt' parameter"
        ));
    }

    #[tokio::test]
    async fn test_sign_raw_missing_psbt_returns_specific_error() {
        let err = sign_raw(test_context(serde_json::json!({})))
            .await
            .expect_err("missing psbt should fail");

        assert!(matches!(
            err,
            Error::InvalidRequest(message)
                if message == "missing 'psbt' parameter - provide a PSBT for signing"
        ));
    }
}
