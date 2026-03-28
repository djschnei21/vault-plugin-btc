mod common;

use common::{request, InMemoryStorage};
use std::sync::Arc;
use vault_plugin_btc::error::Error;
use vault_plugin_btc::router::Router;

#[tokio::test]
async fn combine_psbt_rejects_excessive_batch_size() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());
    let psbts = vec!["cHNidP8BAAoCAAAAAQ==".to_string(); 33];

    let err = router
        .route(
            &request(
                "update",
                "psbt/combine",
                Some(serde_json::json!({ "psbts": psbts })),
            ),
            storage,
        )
        .await
        .expect_err("oversized PSBT combine batches must be rejected");

    assert!(matches!(err, Error::InvalidRequest(message) if message.contains("too many PSBTs")));
}

#[tokio::test]
async fn decode_psbt_rejects_non_string_entries_before_deserialization() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());

    let err = router
        .route(
            &request(
                "update",
                "psbt/combine",
                Some(serde_json::json!({ "psbts": [true, 7, {}] })),
            ),
            storage,
        )
        .await
        .expect_err("non-string PSBT entries must fail validation");

    assert!(matches!(err, Error::InvalidRequest(message) if message.contains("not a string")));
}
