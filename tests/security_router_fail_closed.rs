mod common;

use common::{request, InMemoryStorage};
use std::sync::Arc;
use vault_plugin_btc::router::Router;

#[tokio::test]
async fn valid_empty_config_read_routes_through_test_harness() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());
    let response = router
        .route(&request("read", "config", None), storage)
        .await
        .expect("router should accept a valid read request");

    assert!(response.data.contains("testnet"));
}
