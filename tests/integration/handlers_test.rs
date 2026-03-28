use mockall::mock;
use vault_plugin_btc::storage::Storage;

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
