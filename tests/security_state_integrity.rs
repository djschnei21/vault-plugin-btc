mod common;

use common::{request, InMemoryStorage};
use std::sync::Arc;
use vault_plugin_btc::router::Router;

#[tokio::test]
async fn concurrent_new_address_requests_produce_unique_indices() {
    let storage = Arc::new(InMemoryStorage::new());
    let bootstrap_router = Router::new();

    bootstrap_router
        .route(
            &request(
                "create",
                "wallets/race-wallet",
                Some(serde_json::json!({
                    "network": "testnet",
                    "address_type": "native_segwit"
                })),
            ),
            storage.clone(),
        )
        .await
        .expect("wallet bootstrap must succeed");

    let mut tasks = Vec::new();
    // Use more tasks to increase race probability
    for _ in 0..100 {
        let router = Router::new();
        let storage = storage.clone();
        tasks.push(tokio::spawn(async move {
            let response = router
                .route(
                    &request("update", "wallets/race-wallet/addresses/new", Some(serde_json::json!({}))),
                    storage,
                )
                .await
                .expect("address allocation must succeed");

            let json: serde_json::Value = serde_json::from_str(&response.data).unwrap();
            json["index"].as_u64().unwrap()
        }));
    }

    let mut indices = Vec::new();
    for task in tasks {
        indices.push(task.await.unwrap());
    }
    indices.sort_unstable();

    let expected: Vec<u64> = (0..100).collect();
    assert_eq!(indices, expected);
}
