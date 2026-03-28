use mockall::mock;
use vault_plugin_btc::storage::Storage;
use std::sync::Arc;
use std::collections::HashMap;
use vault_plugin_btc::router::{HandlerContext, Operation};
use vault_plugin_btc::handlers;

mock! {
    pub StorageImpl {}
    #[async_trait::async_trait]
    impl Storage for StorageImpl {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>>;
        async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), Box<dyn std::error::Error>>;
        async fn put_sealed(&self, key: &str, value: Vec<u8>) -> Result<(), Box<dyn std::error::Error>>;
        async fn delete(&self, key: &str) -> Result<(), Box<dyn std::error::Error>>;
        async fn list(&self, prefix: &str) -> Result<Vec<String>, Box<dyn std::error::Error>>;
        async fn get_json<T: serde::de::DeserializeOwned + Send>(&self, key: &str) -> Result<Option<T>, Box<dyn std::error::Error>>;
        async fn put_json<T: serde::Serialize + Send>(&self, key: &str, value: &T) -> Result<(), Box<dyn std::error::Error>>;
        async fn put_json_sealed<T: serde::Serialize + Send>(&self, key: &str, value: &T) -> Result<(), Box<dyn std::error::Error>>;
    }
}

#[tokio::test]
async fn test_create_wallet_invalid_network() {
    let mock_storage = MockStorageImpl::new();
    let storage = Arc::new(mock_storage) as Arc<dyn Storage + Send + Sync>;

    let ctx = HandlerContext {
        operation: Operation::Create,
        path: "wallets/test".to_string(),
        params: [("name".to_string(), "test".to_string())].iter().cloned().collect(),
        data: serde_json::json!({"network": "invalid"}),
        storage,
    };

    let response = handlers::wallets::create_wallet(ctx).await;
    assert!(response.is_err());
}
