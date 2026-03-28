mod common;

use common::{bootstrap_wallet, load_json, request, response_json, seed_json, unix_time_secs, InMemoryStorage};
use std::sync::Arc;
use vault_plugin_btc::error::Error;
use vault_plugin_btc::router::Router;

#[tokio::test]
async fn stale_reservation_is_recovered_and_cleared() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());

    bootstrap_wallet(
        &router,
        storage.clone(),
        "reservation-wallet",
        "testnet",
        "native_segwit",
    )
    .await;

    seed_json(
        storage.clone(),
        "wallets/reservation-wallet/address-reservation",
        serde_json::json!({
            "index": 0,
            "holder": "stale-holder",
            "created_at": 0,
        }),
    )
    .await;

    let response = router
        .route(
            &request(
                "update",
                "wallets/reservation-wallet/addresses/new",
                Some(serde_json::json!({})),
            ),
            storage.clone(),
        )
        .await
        .expect("stale reservation should be recovered");

    let value = response_json(&response);
    assert_eq!(value["index"], 0);
    assert!(value["address"].as_str().is_some_and(|address| !address.is_empty()));
    assert_eq!(
        load_json(storage.clone(), "wallets/reservation-wallet/address-reservation").await,
        None
    );

    let metadata = load_json(storage, "wallets/reservation-wallet/metadata")
        .await
        .expect("metadata should still exist");
    assert_eq!(metadata["next_external_index"], 1);
}

#[tokio::test]
async fn fresh_reservation_blocks_duplicate_allocation() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());

    bootstrap_wallet(
        &router,
        storage.clone(),
        "reservation-wallet",
        "testnet",
        "native_segwit",
    )
    .await;

    seed_json(
        storage.clone(),
        "wallets/reservation-wallet/address-reservation",
        serde_json::json!({
            "index": 0,
            "holder": "other-process",
            "created_at": unix_time_secs(),
        }),
    )
    .await;

    let err = router
        .route(
            &request(
                "update",
                "wallets/reservation-wallet/addresses/new",
                Some(serde_json::json!({})),
            ),
            storage.clone(),
        )
        .await
        .expect_err("fresh reservation should block allocation");

    match err {
        Error::Internal(message) => {
            assert!(message.contains("reservation"), "unexpected error: {message}");
        }
        other => panic!("unexpected error: {other}"),
    }

    let metadata = load_json(storage.clone(), "wallets/reservation-wallet/metadata")
        .await
        .expect("metadata should still exist");
    assert_eq!(metadata["next_external_index"], 0);

    let reservation = load_json(storage, "wallets/reservation-wallet/address-reservation")
        .await
        .expect("fresh reservation should remain in place");
    assert_eq!(reservation["index"], 0);
    assert_eq!(reservation["holder"], "other-process");
}
