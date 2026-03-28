use super::validation::validate_json;
use crate::error::Error;
use crate::handlers::ok_response;
use crate::proto::pb::Response as PbResponse;
use crate::router::HandlerContext;
use base64::Engine;
use bitcoin::psbt::Psbt;
use serde::Deserialize;
use tracing::{error, info};

#[derive(Deserialize)]
struct PsbtStringRequest {
    psbt: String,
}

#[derive(Deserialize)]
struct CombinePsbtRequest {
    psbts: Vec<String>,
}

#[derive(Deserialize)]
struct CreatePsbtInput {
    txid: String,
    vout: u32,
}

#[derive(Deserialize)]
struct CreatePsbtOutput {
    address: String,
    amount: u64,
}

#[derive(Deserialize)]
struct CreatePsbtRequest {
    inputs: Vec<CreatePsbtInput>,
    outputs: Vec<CreatePsbtOutput>,
}

const MAX_COMBINE_PSBTS: usize = 32;
const MAX_CREATE_INPUTS: usize = 128;
const MAX_CREATE_OUTPUTS: usize = 128;

fn parse_psbt_string_request(data: &serde_json::Value) -> Result<PsbtStringRequest, Error> {
    if data.get("psbt").is_none() {
        return Err(Error::InvalidRequest(
            "missing 'psbt' parameter".to_string(),
        ));
    }

    validate_json(data)
}

fn validate_combine_psbt_entries(data: &serde_json::Value) -> Result<(), Error> {
    let Some(psbts) = data.get("psbts").and_then(serde_json::Value::as_array) else {
        return Ok(());
    };

    for (i, psbt) in psbts.iter().enumerate() {
        if !psbt.is_string() {
            return Err(Error::InvalidRequest(format!(
                "psbt at index {i} is not a string"
            )));
        }
    }

    Ok(())
}

fn validate_create_psbt_entries(data: &serde_json::Value) -> Result<(), Error> {
    fn validate_nested_field(
        object: &serde_json::Map<String, serde_json::Value>,
        entry_kind: &str,
        index: usize,
        field: &str,
        expected_type: &str,
        is_valid: impl FnOnce(&serde_json::Value) -> bool,
    ) -> Result<(), Error> {
        let Some(value) = object.get(field) else {
            return Err(Error::InvalidRequest(format!(
                "{entry_kind} {index}: missing '{field}'"
            )));
        };

        if !is_valid(value) {
            return Err(Error::InvalidRequest(format!(
                "{entry_kind} {index}: '{field}' must be a {expected_type}"
            )));
        }

        Ok(())
    }

    if let Some(inputs) = data.get("inputs").and_then(serde_json::Value::as_array) {
        for (i, input) in inputs.iter().enumerate() {
            let Some(input) = input.as_object() else {
                return Err(Error::InvalidRequest(format!("input {i} is not an object")));
            };

            validate_nested_field(input, "input", i, "txid", "string", |value| {
                value.is_string()
            })?;
            validate_nested_field(input, "input", i, "vout", "u32", |value| {
                value
                    .as_u64()
                    .is_some_and(|vout| u32::try_from(vout).is_ok())
            })?;
        }
    }

    if let Some(outputs) = data.get("outputs").and_then(serde_json::Value::as_array) {
        for (i, output) in outputs.iter().enumerate() {
            let Some(output) = output.as_object() else {
                return Err(Error::InvalidRequest(format!(
                    "output {i} is not an object"
                )));
            };

            validate_nested_field(output, "output", i, "address", "string", |value| {
                value.is_string()
            })?;
            validate_nested_field(output, "output", i, "amount", "u64", |value| {
                value.as_u64().is_some()
            })?;
        }
    }

    Ok(())
}

fn parse_combine_psbt_request(data: &serde_json::Value) -> Result<CombinePsbtRequest, Error> {
    if data.get("psbts").is_none() {
        return Err(Error::InvalidRequest(
            "missing 'psbts' array parameter".to_string(),
        ));
    }

    validate_combine_psbt_entries(data)?;

    let request: CombinePsbtRequest = validate_json(data)?;

    if request.psbts.len() > MAX_COMBINE_PSBTS {
        return Err(Error::InvalidRequest(format!(
            "too many PSBTs: maximum is {MAX_COMBINE_PSBTS}"
        )));
    }

    Ok(request)
}

fn parse_create_psbt_request(data: &serde_json::Value) -> Result<CreatePsbtRequest, Error> {
    if data.get("inputs").is_none() {
        return Err(Error::InvalidRequest("missing 'inputs' array".to_string()));
    }
    if data.get("outputs").is_none() {
        return Err(Error::InvalidRequest("missing 'outputs' array".to_string()));
    }

    validate_create_psbt_entries(data)?;

    let request: CreatePsbtRequest = validate_json(data)?;

    if request.inputs.len() > MAX_CREATE_INPUTS {
        return Err(Error::InvalidRequest(format!(
            "too many inputs: maximum is {MAX_CREATE_INPUTS}"
        )));
    }
    if request.outputs.len() > MAX_CREATE_OUTPUTS {
        return Err(Error::InvalidRequest(format!(
            "too many outputs: maximum is {MAX_CREATE_OUTPUTS}"
        )));
    }

    Ok(request)
}

/// POST /psbt/decode - Decode and inspect a PSBT.
///
/// Request data:
/// - `psbt`: Base64-encoded PSBT string
pub async fn decode_psbt(ctx: HandlerContext) -> Result<PbResponse, Error> {
    let request = parse_psbt_string_request(&ctx.data)?;

    info!("Decoding PSBT");

    let psbt_bytes = base64::engine::general_purpose::STANDARD
        .decode(&request.psbt)
        .map_err(|e| {
            error!(error = %e, "Invalid PSBT base64 for decode");
            Error::InvalidPsbt(format!("invalid base64: {e}"))
        })?;

    let psbt = Psbt::deserialize(&psbt_bytes).map_err(|e| {
        error!(error = %e, "Invalid PSBT for decode");
        Error::InvalidPsbt(format!("invalid PSBT: {e}"))
    })?;

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
    let request = parse_combine_psbt_request(&ctx.data)?;

    info!(psbt_count = request.psbts.len(), "Combining PSBTs");

    if request.psbts.is_empty() {
        return Err(Error::InvalidRequest("empty psbts array".to_string()));
    }

    let mut base_psbt: Option<Psbt> = None;

    for (i, psbt_b64) in request.psbts.iter().enumerate() {
        let psbt_bytes = base64::engine::general_purpose::STANDARD
            .decode(psbt_b64)
            .map_err(|e| {
                error!(index = i, error = %e, "Invalid PSBT base64 for combine");
                Error::InvalidPsbt(format!("invalid base64 at index {i}: {e}"))
            })?;

        let psbt = Psbt::deserialize(&psbt_bytes).map_err(|e| {
            error!(index = i, error = %e, "Invalid PSBT for combine");
            Error::InvalidPsbt(format!("invalid PSBT at index {i}: {e}"))
        })?;

        match &mut base_psbt {
            None => base_psbt = Some(psbt),
            Some(base) => {
                base.combine(psbt)
                    .map_err(|e| Error::InvalidPsbt(format!("failed to combine PSBTs: {e}")))?;
            }
        }
    }

    let combined = base_psbt.unwrap();
    let combined_b64 = base64::engine::general_purpose::STANDARD.encode(combined.serialize());

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
    let request = parse_psbt_string_request(&ctx.data)?;

    info!("Finalizing PSBT");

    let psbt_bytes = base64::engine::general_purpose::STANDARD
        .decode(&request.psbt)
        .map_err(|e| {
            error!(error = %e, "Invalid PSBT base64 for finalize");
            Error::InvalidPsbt(format!("invalid base64: {e}"))
        })?;

    let psbt = Psbt::deserialize(&psbt_bytes).map_err(|e| {
        error!(error = %e, "Invalid PSBT for finalize");
        Error::InvalidPsbt(format!("invalid PSBT: {e}"))
    })?;

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

    let request = parse_create_psbt_request(&ctx.data)?;

    info!(
        input_count = request.inputs.len(),
        output_count = request.outputs.len(),
        "Creating PSBT"
    );

    if request.inputs.is_empty() {
        return Err(Error::InvalidRequest("inputs array is empty".to_string()));
    }
    if request.outputs.is_empty() {
        return Err(Error::InvalidRequest("outputs array is empty".to_string()));
    }

    // Parse inputs
    let mut tx_inputs = Vec::new();
    for (i, input) in request.inputs.iter().enumerate() {
        let txid = Txid::from_str(&input.txid)
            .map_err(|e| Error::InvalidRequest(format!("input {i}: invalid txid: {e}")))?;

        tx_inputs.push(TxIn {
            previous_output: OutPoint::new(txid, input.vout),
            ..Default::default()
        });
    }

    // Parse outputs
    let mut tx_outputs = Vec::new();
    for (i, output) in request.outputs.iter().enumerate() {
        let address: bitcoin::Address<bitcoin::address::NetworkUnchecked> = output
            .address
            .parse()
            .map_err(|e| Error::InvalidRequest(format!("output {i}: invalid address: {e}")))?;

        tx_outputs.push(TxOut {
            value: Amount::from_sat(output.amount),
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
            params: HashMap::new(),
            data,
            storage: Arc::new(NoopStorage),
        }
    }

    #[tokio::test]
    async fn test_decode_psbt_missing_psbt_returns_specific_error() {
        let err = decode_psbt(test_context(serde_json::json!({})))
            .await
            .expect_err("missing psbt should fail");

        assert!(matches!(
            err,
            Error::InvalidRequest(message) if message == "missing 'psbt' parameter"
        ));
    }

    #[tokio::test]
    async fn test_finalize_psbt_missing_psbt_returns_specific_error() {
        let err = finalize_psbt(test_context(serde_json::json!({})))
            .await
            .expect_err("missing psbt should fail");

        assert!(matches!(
            err,
            Error::InvalidRequest(message) if message == "missing 'psbt' parameter"
        ));
    }

    #[tokio::test]
    async fn test_combine_psbt_missing_psbts_returns_specific_error() {
        let err = combine_psbt(test_context(serde_json::json!({})))
            .await
            .expect_err("missing psbts should fail");

        assert!(matches!(
            err,
            Error::InvalidRequest(message) if message == "missing 'psbts' array parameter"
        ));
    }

    #[tokio::test]
    async fn test_combine_psbt_rejects_non_string_entries() {
        let err = combine_psbt(test_context(serde_json::json!({
            "psbts": [123]
        })))
        .await
        .expect_err("non-string psbt entries should fail");

        assert!(matches!(
            err,
            Error::InvalidRequest(message) if message == "psbt at index 0 is not a string"
        ));
    }

    #[tokio::test]
    async fn test_create_psbt_missing_inputs_returns_specific_error() {
        let err = create_psbt(test_context(serde_json::json!({
            "outputs": []
        })))
        .await
        .expect_err("missing inputs should fail");

        assert!(matches!(
            err,
            Error::InvalidRequest(message) if message == "missing 'inputs' array"
        ));
    }

    #[tokio::test]
    async fn test_create_psbt_missing_outputs_returns_specific_error() {
        let err = create_psbt(test_context(serde_json::json!({
            "inputs": []
        })))
        .await
        .expect_err("missing outputs should fail");

        assert!(matches!(
            err,
            Error::InvalidRequest(message) if message == "missing 'outputs' array"
        ));
    }

    #[tokio::test]
    async fn test_create_psbt_rejects_input_missing_txid() {
        let err = create_psbt(test_context(serde_json::json!({
            "inputs": [{"vout": 0}],
            "outputs": [{"address": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "amount": 1}]
        })))
        .await
        .expect_err("input missing txid should fail");

        assert!(matches!(
            err,
            Error::InvalidRequest(message) if message == "input 0: missing 'txid'"
        ));
    }

    #[tokio::test]
    async fn test_create_psbt_rejects_input_txid_wrong_type() {
        let err = create_psbt(test_context(serde_json::json!({
            "inputs": [{"txid": 123, "vout": 0}],
            "outputs": [{"address": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "amount": 1}]
        })))
        .await
        .expect_err("input txid wrong type should fail");

        assert!(matches!(
            err,
            Error::InvalidRequest(message) if message == "input 0: 'txid' must be a string"
        ));
    }

    #[tokio::test]
    async fn test_create_psbt_rejects_input_vout_wrong_type() {
        let err = create_psbt(test_context(serde_json::json!({
            "inputs": [{"txid": "0000000000000000000000000000000000000000000000000000000000000000", "vout": "0"}],
            "outputs": [{"address": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "amount": 1}]
        })))
        .await
        .expect_err("input vout wrong type should fail");

        assert!(matches!(
            err,
            Error::InvalidRequest(message) if message == "input 0: 'vout' must be a u32"
        ));
    }

    #[tokio::test]
    async fn test_create_psbt_rejects_output_missing_amount() {
        let err = create_psbt(test_context(serde_json::json!({
            "inputs": [{"txid": "0000000000000000000000000000000000000000000000000000000000000000", "vout": 0}],
            "outputs": [{"address": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"}]
        })))
        .await
        .expect_err("output missing amount should fail");

        assert!(matches!(
            err,
            Error::InvalidRequest(message) if message == "output 0: missing 'amount'"
        ));
    }

    #[tokio::test]
    async fn test_create_psbt_rejects_output_address_wrong_type() {
        let err = create_psbt(test_context(serde_json::json!({
            "inputs": [{"txid": "0000000000000000000000000000000000000000000000000000000000000000", "vout": 0}],
            "outputs": [{"address": 123, "amount": 1}]
        })))
        .await
        .expect_err("output address wrong type should fail");

        assert!(matches!(
            err,
            Error::InvalidRequest(message) if message == "output 0: 'address' must be a string"
        ));
    }

    #[tokio::test]
    async fn test_create_psbt_rejects_output_amount_wrong_type() {
        let err = create_psbt(test_context(serde_json::json!({
            "inputs": [{"txid": "0000000000000000000000000000000000000000000000000000000000000000", "vout": 0}],
            "outputs": [{"address": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "amount": "1"}]
        })))
        .await
        .expect_err("output amount wrong type should fail");

        assert!(matches!(
            err,
            Error::InvalidRequest(message) if message == "output 0: 'amount' must be a u64"
        ));
    }
}
