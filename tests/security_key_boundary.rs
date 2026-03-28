mod common;

use common::{request, InMemoryStorage};
use std::sync::Arc;
use vault_plugin_btc::error::Error;
use vault_plugin_btc::router::Router;

#[tokio::test]
async fn derive_key_rejects_unknown_keychain() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());

    let err = router
        .route(
            &request(
                "update",
                "wallets/test-wallet/keys/derive",
                Some(serde_json::json!({
                    "path": "7",
                    "keychain": "sideways"
                })),
            ),
            storage,
        )
        .await
        .expect_err("unknown keychain values must be rejected");

    assert!(matches!(err, Error::InvalidRequest(message) if message.contains("invalid keychain")));
}

#[tokio::test]
async fn derive_key_rejects_multi_segment_path() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());

    let err = router
        .route(
            &request(
                "update",
                "wallets/test-wallet/keys/derive",
                Some(serde_json::json!({
                    "path": "0/7",
                    "keychain": "external"
                })),
            ),
            storage,
        )
        .await
        .expect_err("multi-segment derivation must be rejected for this endpoint");

    assert!(matches!(err, Error::InvalidRequest(message) if message.contains("single unhardened index")));
}
