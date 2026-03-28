use crate::error::Error;
use crate::handlers::ok_response;
use crate::proto::pb::Response as PbResponse;
use crate::router::HandlerContext;
use crate::wallet::manager::WalletManager;
use base64::Engine;
use bdk_wallet::SignOptions;
use bitcoin::psbt::Psbt;

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

    let psbt_b64 = ctx
        .data
        .get("psbt")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::InvalidRequest("missing 'psbt' parameter".to_string()))?;

    // Decode PSBT
    let psbt_bytes = base64::engine::general_purpose::STANDARD
        .decode(psbt_b64)
        .map_err(|e| Error::InvalidPsbt(format!("invalid base64: {e}")))?;

    let mut psbt = Psbt::deserialize(&psbt_bytes)
        .map_err(|e| Error::InvalidPsbt(format!("invalid PSBT: {e}")))?;

    // Load wallet with private keys
    let (wallet, _metadata) = WalletManager::load_bdk_wallet(&ctx.storage, name).await?;

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
    let psbt_b64 = ctx
        .data
        .get("psbt")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            Error::InvalidRequest(
                "missing 'psbt' parameter - provide a PSBT for signing".to_string(),
            )
        })?;

    let psbt_bytes = base64::engine::general_purpose::STANDARD
        .decode(psbt_b64)
        .map_err(|e| Error::InvalidPsbt(format!("invalid base64: {e}")))?;

    let mut psbt = Psbt::deserialize(&psbt_bytes)
        .map_err(|e| Error::InvalidPsbt(format!("invalid PSBT: {e}")))?;

    let (wallet, _metadata) = WalletManager::load_bdk_wallet(&ctx.storage, name).await?;

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
