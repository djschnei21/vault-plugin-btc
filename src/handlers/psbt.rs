use crate::error::Error;
use crate::handlers::ok_response;
use crate::proto::pb::Response as PbResponse;
use crate::router::HandlerContext;
use base64::Engine;
use bitcoin::psbt::Psbt;

/// POST /psbt/decode - Decode and inspect a PSBT.
///
/// Request data:
/// - `psbt`: Base64-encoded PSBT string
pub async fn decode_psbt(ctx: HandlerContext) -> Result<PbResponse, Error> {
    let psbt_b64 = ctx
        .data
        .get("psbt")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::InvalidRequest("missing 'psbt' parameter".to_string()))?;

    let psbt_bytes = base64::engine::general_purpose::STANDARD
        .decode(psbt_b64)
        .map_err(|e| Error::InvalidPsbt(format!("invalid base64: {e}")))?;

    let psbt = Psbt::deserialize(&psbt_bytes)
        .map_err(|e| Error::InvalidPsbt(format!("invalid PSBT: {e}")))?;

    // Extract information from the PSBT
    let inputs: Vec<serde_json::Value> = psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            let mut info = serde_json::json!({
                "index": i,
            });

            if let Some(ref utxo) = input.witness_utxo {
                info["witness_utxo"] = serde_json::json!({
                    "value": utxo.value.to_sat(),
                    "script_pubkey": utxo.script_pubkey.to_hex_string(),
                });
            }

            if let Some(ref tx) = input.non_witness_utxo {
                info["non_witness_utxo_txid"] =
                    serde_json::Value::String(tx.compute_txid().to_string());
            }

            let sig_count = input.partial_sigs.len();
            info["partial_signatures"] = serde_json::Value::Number(sig_count.into());

            if !input.bip32_derivation.is_empty() {
                info["bip32_derivations"] =
                    serde_json::Value::Number(input.bip32_derivation.len().into());
            }

            if input.final_script_sig.is_some() {
                info["has_final_script_sig"] = serde_json::Value::Bool(true);
            }

            if input.final_script_witness.is_some() {
                info["has_final_script_witness"] = serde_json::Value::Bool(true);
            }

            info
        })
        .collect();

    let outputs: Vec<serde_json::Value> = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .map(|(i, output)| {
            serde_json::json!({
                "index": i,
                "value": output.value.to_sat(),
                "script_pubkey": output.script_pubkey.to_hex_string(),
            })
        })
        .collect();

    let tx = &psbt.unsigned_tx;
    Ok(ok_response(serde_json::json!({
        "txid": tx.compute_txid().to_string(),
        "version": tx.version.0,
        "lock_time": tx.lock_time.to_consensus_u32(),
        "input_count": inputs.len(),
        "output_count": outputs.len(),
        "inputs": inputs,
        "outputs": outputs,
    })))
}

/// POST /psbt/combine - Combine multiple PSBTs.
///
/// Request data:
/// - `psbts`: Array of base64-encoded PSBT strings
pub async fn combine_psbt(ctx: HandlerContext) -> Result<PbResponse, Error> {
    let psbts_val = ctx
        .data
        .get("psbts")
        .and_then(|v| v.as_array())
        .ok_or_else(|| Error::InvalidRequest("missing 'psbts' array parameter".to_string()))?;

    if psbts_val.is_empty() {
        return Err(Error::InvalidRequest("empty psbts array".to_string()));
    }

    let mut base_psbt: Option<Psbt> = None;

    for (i, psbt_val) in psbts_val.iter().enumerate() {
        let psbt_b64 = psbt_val.as_str().ok_or_else(|| {
            Error::InvalidRequest(format!("psbt at index {i} is not a string"))
        })?;

        let psbt_bytes = base64::engine::general_purpose::STANDARD
            .decode(psbt_b64)
            .map_err(|e| Error::InvalidPsbt(format!("invalid base64 at index {i}: {e}")))?;

        let psbt = Psbt::deserialize(&psbt_bytes)
            .map_err(|e| Error::InvalidPsbt(format!("invalid PSBT at index {i}: {e}")))?;

        match &mut base_psbt {
            None => base_psbt = Some(psbt),
            Some(base) => {
                base.combine(psbt)
                    .map_err(|e| Error::InvalidPsbt(format!("failed to combine PSBTs: {e}")))?;
            }
        }
    }

    let combined = base_psbt.unwrap();
    let combined_b64 =
        base64::engine::general_purpose::STANDARD.encode(combined.serialize());

    Ok(ok_response(serde_json::json!({
        "psbt": combined_b64,
    })))
}

/// POST /psbt/finalize - Finalize a PSBT.
///
/// Attempts to finalize all inputs. If successful, extracts the raw transaction.
///
/// Request data:
/// - `psbt`: Base64-encoded PSBT string
pub async fn finalize_psbt(ctx: HandlerContext) -> Result<PbResponse, Error> {
    let psbt_b64 = ctx
        .data
        .get("psbt")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::InvalidRequest("missing 'psbt' parameter".to_string()))?;

    let psbt_bytes = base64::engine::general_purpose::STANDARD
        .decode(psbt_b64)
        .map_err(|e| Error::InvalidPsbt(format!("invalid base64: {e}")))?;

    let psbt = Psbt::deserialize(&psbt_bytes)
        .map_err(|e| Error::InvalidPsbt(format!("invalid PSBT: {e}")))?;

    // Try to extract the transaction (this only works if all inputs are finalized)
    match psbt.extract_tx() {
        Ok(tx) => {
            let tx_hex = hex::encode(bitcoin::consensus::serialize(&tx));
            let txid = tx.compute_txid();
            Ok(ok_response(serde_json::json!({
                "complete": true,
                "signed_tx": tx_hex,
                "txid": txid.to_string(),
            })))
        }
        Err(e) => {
            // Return the PSBT as-is with a note that it's not complete
            let psbt_out = base64::engine::general_purpose::STANDARD.encode(psbt_bytes);
            Ok(ok_response(serde_json::json!({
                "complete": false,
                "psbt": psbt_out,
                "error": format!("PSBT not fully finalized: {e}"),
            })))
        }
    }
}

/// POST /psbt/create - Create a new PSBT.
///
/// This is a utility endpoint for constructing PSBTs from raw components.
///
/// Request data:
/// - `inputs`: Array of `{"txid": "...", "vout": N}` objects
/// - `outputs`: Array of `{"address": "...", "amount": N}` objects (amount in satoshis)
pub async fn create_psbt(ctx: HandlerContext) -> Result<PbResponse, Error> {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, Transaction, TxIn, TxOut, Txid};
    use std::str::FromStr;

    let inputs_val = ctx
        .data
        .get("inputs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| Error::InvalidRequest("missing 'inputs' array".to_string()))?;

    let outputs_val = ctx
        .data
        .get("outputs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| Error::InvalidRequest("missing 'outputs' array".to_string()))?;

    if inputs_val.is_empty() {
        return Err(Error::InvalidRequest("inputs array is empty".to_string()));
    }
    if outputs_val.is_empty() {
        return Err(Error::InvalidRequest("outputs array is empty".to_string()));
    }

    // Parse inputs
    let mut tx_inputs = Vec::new();
    for (i, input) in inputs_val.iter().enumerate() {
        let txid_str = input
            .get("txid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InvalidRequest(format!("input {i}: missing 'txid'")))?;
        let vout = input
            .get("vout")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| Error::InvalidRequest(format!("input {i}: missing 'vout'")))?
            as u32;

        let txid = Txid::from_str(txid_str)
            .map_err(|e| Error::InvalidRequest(format!("input {i}: invalid txid: {e}")))?;

        tx_inputs.push(TxIn {
            previous_output: OutPoint::new(txid, vout),
            ..Default::default()
        });
    }

    // Parse outputs
    let mut tx_outputs = Vec::new();
    for (i, output) in outputs_val.iter().enumerate() {
        let address_str = output
            .get("address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InvalidRequest(format!("output {i}: missing 'address'")))?;
        let amount_sats = output
            .get("amount")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| Error::InvalidRequest(format!("output {i}: missing 'amount'")))?;

        let address: bitcoin::Address<bitcoin::address::NetworkUnchecked> = address_str
            .parse()
            .map_err(|e| Error::InvalidRequest(format!("output {i}: invalid address: {e}")))?;

        tx_outputs.push(TxOut {
            value: Amount::from_sat(amount_sats),
            script_pubkey: address.assume_checked().script_pubkey(),
        });
    }

    // Build unsigned transaction
    let unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: tx_inputs,
        output: tx_outputs,
    };

    // Create PSBT from unsigned transaction
    let psbt = Psbt::from_unsigned_tx(unsigned_tx)
        .map_err(|e| Error::InvalidPsbt(format!("failed to create PSBT: {e}")))?;

    let psbt_b64 = base64::engine::general_purpose::STANDARD.encode(psbt.serialize());

    Ok(ok_response(serde_json::json!({
        "psbt": psbt_b64,
        "txid": psbt.unsigned_tx.compute_txid().to_string(),
    })))
}
