mod common;

use base64::Engine;
use bitcoin::hashes::Hash;
use bitcoin::absolute::LockTime;
use bitcoin::address::NetworkUnchecked;
use bitcoin::psbt::Psbt;
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid};
use common::{bootstrap_wallet, request, response_json, InMemoryStorage};
use std::str::FromStr;
use std::sync::Arc;
use vault_plugin_btc::error::Error;
use vault_plugin_btc::router::Router;

fn psbt_base64_without_utxo_context() -> String {
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

    let psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("PSBT creation must succeed");
    base64::engine::general_purpose::STANDARD.encode(psbt.serialize())
}

fn psbt_base64_with_nested_segwit_input_missing_redeem_script(script_pubkey: ScriptBuf) -> String {
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

    base64::engine::general_purpose::STANDARD.encode(psbt.serialize())
}

#[tokio::test]
async fn sign_rejects_psbt_without_utxo_script_context() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());

    bootstrap_wallet(&router, storage.clone(), "policy-wallet", "testnet", "native_segwit").await;

    let err = router
        .route(
            &request(
                "update",
                "wallets/policy-wallet/sign",
                Some(serde_json::json!({
                    "psbt": psbt_base64_without_utxo_context(),
                })),
            ),
            storage,
        )
        .await
        .expect_err("signing must reject missing UTXO script context");

    assert!(matches!(
        err,
        Error::InvalidRequest(message) if message.contains("UTXO") && message.contains("context")
    ));
}

#[tokio::test]
async fn sign_rejects_nested_segwit_without_redeem_script_context() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());

    bootstrap_wallet(&router, storage.clone(), "policy-wallet", "testnet", "nested_segwit").await;

    let address_response = router
        .route(
            &request(
                "update",
                "wallets/policy-wallet/addresses/new",
                Some(serde_json::json!({})),
            ),
            storage.clone(),
        )
        .await
        .expect("address derivation must succeed");
    let address_value = response_json(&address_response);
    let address = Address::<NetworkUnchecked>::from_str(
        address_value["address"]
            .as_str()
            .expect("address response must contain string address"),
    )
    .expect("wallet address must parse")
    .assume_checked();

    let err = router
        .route(
            &request(
                "update",
                "wallets/policy-wallet/sign",
                Some(serde_json::json!({
                    "psbt": psbt_base64_with_nested_segwit_input_missing_redeem_script(address.script_pubkey()),
                })),
            ),
            storage,
        )
        .await
        .expect_err("nested segwit signing must reject missing redeem script context");

    assert!(matches!(
        err,
        Error::InvalidRequest(message) if message.contains("redeem") && message.contains("nested-segwit")
    ));
}
