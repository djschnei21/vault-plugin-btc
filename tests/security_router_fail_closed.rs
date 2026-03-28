mod common;

use common::{request, InMemoryStorage};
use std::sync::Arc;
use vault_plugin_btc::error::Error;
use vault_plugin_btc::proto::pb::Request as PbRequest;
use vault_plugin_btc::router::Router;

#[tokio::test]
async fn invalid_json_request_is_rejected() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());
    let request = PbRequest {
        operation: "update".to_string(),
        path: "config".to_string(),
        data: "{\"network\":".to_string(),
        ..Default::default()
    };

    let err = router
        .route(&request, storage)
        .await
        .expect_err("invalid JSON must not be coerced into an empty object");

    assert!(matches!(err, Error::InvalidRequest(message) if message.contains("invalid JSON body")));
}

#[tokio::test]
async fn read_does_not_match_list_route() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());

    let err = router
        .route(&request("read", "wallets", None), storage)
        .await
        .expect_err("read must not match the list-only route");

    assert!(matches!(err, Error::UnsupportedOperation(_, _) | Error::UnsupportedPath(_)));
}

#[tokio::test]
async fn oversized_request_body_is_rejected() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());
    let too_large = "a".repeat(65 * 1024);
    let request = PbRequest {
        operation: "update".to_string(),
        path: "config".to_string(),
        data: format!("{{\"network\":\"{}\"}}", too_large),
        ..Default::default()
    };

    let err = router
        .route(&request, storage)
        .await
        .expect_err("oversized request bodies must be rejected early");

    assert!(matches!(err, Error::InvalidRequest(message) if message.contains("request body too large")));
}
