mod common;

use common::{bootstrap_wallet, request, response_json, InMemoryStorage};
use std::sync::Arc;
use vault_plugin_btc::router::Router;

#[tokio::test]
async fn wallet_read_omits_descriptors_and_returns_minimal_metadata() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());

    bootstrap_wallet(
        &router,
        storage.clone(),
        "privacy-wallet",
        "testnet",
        "native_segwit",
    )
    .await;

    let response = router
        .route(
            &request("read", "wallets/privacy-wallet", None),
            storage,
        )
        .await
        .expect("wallet read must succeed");
    let value = response_json(&response);
    let object = value
        .as_object()
        .expect("wallet read response must be a JSON object");

    assert_eq!(object.len(), 8);
    assert_eq!(value["name"], "privacy-wallet");
    assert_eq!(value["network"], "testnet");
    assert_eq!(value["address_type"], "native_segwit");
    assert!(value["created_at"].is_u64());
    assert_eq!(value["next_external_index"], 0);
    assert_eq!(value["next_internal_index"], 0);
    assert_eq!(value["has_external_keychain"], true);
    assert_eq!(value["has_internal_keychain"], true);
    assert!(object.get("external_descriptor").is_none());
    assert!(object.get("internal_descriptor").is_none());
}

#[tokio::test]
async fn keys_read_omits_descriptors_and_returns_presence_flags() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());

    bootstrap_wallet(
        &router,
        storage.clone(),
        "privacy-wallet",
        "testnet",
        "native_segwit",
    )
    .await;

    let response = router
        .route(
            &request("read", "wallets/privacy-wallet/keys", None),
            storage,
        )
        .await
        .expect("keys read must succeed");
    let value = response_json(&response);
    let object = value
        .as_object()
        .expect("keys read response must be a JSON object");

    assert_eq!(object.len(), 5);
    assert_eq!(value["name"], "privacy-wallet");
    assert_eq!(value["network"], "testnet");
    assert_eq!(value["address_type"], "native_segwit");
    assert_eq!(value["has_external_keychain"], true);
    assert_eq!(value["has_internal_keychain"], true);
    assert!(object.get("external_descriptor").is_none());
    assert!(object.get("internal_descriptor").is_none());
}

#[tokio::test]
async fn derive_key_still_supports_valid_single_index_requests() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());

    bootstrap_wallet(
        &router,
        storage.clone(),
        "privacy-wallet",
        "testnet",
        "native_segwit",
    )
    .await;

    let response = router
        .route(
            &request(
                "update",
                "wallets/privacy-wallet/keys/derive",
                Some(serde_json::json!({
                    "path": "7",
                    "keychain": "external"
                })),
            ),
            storage,
        )
        .await
        .expect("single-index key derivation must succeed");
    let value = response_json(&response);

    assert_eq!(value["index"], 7);
    assert_eq!(value["keychain"], "external");
    assert_eq!(value["derivation_path"], "7");
    assert!(value["address"].as_str().is_some_and(|address| !address.is_empty()));
}
