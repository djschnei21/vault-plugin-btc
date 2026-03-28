use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::sync::Arc;
use tokio::sync::Mutex;
use vault_plugin_btc::proto::pb::Request as PbRequest;
use vault_plugin_btc::proto::pb::Response as PbResponse;
use vault_plugin_btc::router::Router;
use vault_plugin_btc::storage::Storage;

#[derive(Default, Clone)]
pub struct InMemoryStorage {
    inner: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

#[allow(dead_code)]
pub fn response_json(response: &PbResponse) -> Value {
    serde_json::from_str(&response.data).expect("response should contain valid JSON")
}

#[allow(dead_code)]
pub async fn bootstrap_wallet(
    router: &Router,
    storage: Arc<InMemoryStorage>,
    name: &str,
    network: &str,
    address_type: &str,
) {
    router
        .route(
            &request(
                "create",
                &format!("wallets/{name}"),
                Some(serde_json::json!({
                    "network": network,
                    "address_type": address_type,
                })),
            ),
            storage,
        )
        .await
        .expect("wallet bootstrap must succeed");
}

#[async_trait]
impl Storage for InMemoryStorage {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, Box<dyn StdError>> {
        Ok(self.inner.lock().await.get(key).cloned())
    }

    async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), Box<dyn StdError>> {
        self.inner.lock().await.insert(key.to_string(), value);
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), Box<dyn StdError>> {
        self.inner.lock().await.remove(key);
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, Box<dyn StdError>> {
        let mut keys = self
            .inner
            .lock()
            .await
            .keys()
            .filter_map(|key| key.strip_prefix(prefix).map(str::to_string))
            .collect::<Vec<_>>();
        keys.sort();
        keys.dedup();
        Ok(keys)
    }

    async fn put_sealed(&self, key: &str, value: Vec<u8>) -> Result<(), Box<dyn StdError>> {
        self.put(key, value).await
    }
}

pub fn request(operation: &str, path: &str, data: Option<Value>) -> PbRequest {
    PbRequest {
        operation: operation.to_string(),
        path: path.to_string(),
        data: data.map(|value| value.to_string()).unwrap_or_default(),
        ..Default::default()
    }
}
