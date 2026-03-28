mod vault_storage;

pub use vault_storage::VaultStorageImpl as VaultStorage;

use async_trait::async_trait;

#[async_trait]
pub trait Storage {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>>;
    async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), Box<dyn std::error::Error>>;
    async fn delete(&self, key: &str) -> Result<(), Box<dyn std::error::Error>>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>, Box<dyn std::error::Error>>;
    async fn put_sealed(&self, key: &str, value: Vec<u8>)
        -> Result<(), Box<dyn std::error::Error>>;
}
