use mockall::mock;
use vault_plugin_btc::storage::Storage;

mock! {
    StorageMock {}
    impl Storage for StorageMock {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>>;
        async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), Box<dyn std::error::Error>>;
        async fn delete(&self, key: &str) -> Result<(), Box<dyn std::error::Error>>;
        async fn list(&self, prefix: &str) -> Result<Vec<String>, Box<dyn std::error::Error>>;
        async fn put_sealed(&self, key: &str, value: Vec<u8>) -> Result<(), Box<dyn std::error::Error>>;
    }
}

#[tokio::test]
async fn test_create_wallet_success() {
    let mut mock_storage = MockStorageMock::new();
    mock_storage.expect_get().returning(|_| Ok(None)); // for checking if exists
    mock_storage.expect_put_sealed().returning(|_, _| Ok(()));
    mock_storage.expect_put().returning(|_, _| Ok(()));

    let storage = std::sync::Arc::new(mock_storage) as std::sync::Arc<dyn VaultStorage + Send + Sync>;

    // Create HandlerContext
    let ctx = vault_plugin_btc::router::HandlerContext {
        operation: vault_plugin_btc::router::Operation::Create,
        path: "wallets/test".to_string(),
        params: [("name".to_string(), "test".to_string())].iter().cloned().collect(),
        data: serde_json::json!({
            "network": "testnet",
            "address_type": "p2wpkh"
        }),
        storage,
    };

    let response = vault_plugin_btc::handlers::wallets::create_wallet(ctx).await;
    assert!(response.is_ok());
}