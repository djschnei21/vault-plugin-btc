use crate::error::Error;
use crate::proto::pb::{
    storage_client::StorageClient, StorageDeleteArgs, StorageGetArgs, StorageListArgs,
    StoragePutArgs, StorageEntry,
};
use tonic::transport::Channel;

/// Wrapper around the Vault Storage gRPC client.
/// Provides async key-value storage backed by Vault's encrypted storage.
#[derive(Debug, Clone)]
pub struct VaultStorage {
    client: StorageClient<Channel>,
}

impl VaultStorage {
    pub fn new(client: StorageClient<Channel>) -> Self {
        Self { client }
    }

    /// Get a value from storage by key.
    pub async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, Error> {
        let resp = self
            .client
            .clone()
            .get(StorageGetArgs {
                key: key.to_string(),
            })
            .await
            .map_err(|e| Error::Storage(e.to_string()))?
            .into_inner();

        if !resp.err.is_empty() {
            return Err(Error::Storage(resp.err));
        }

        Ok(resp.entry.map(|e| e.value))
    }

    /// Store a value in storage.
    pub async fn put(&self, key: &str, value: &[u8]) -> Result<(), Error> {
        let resp = self
            .client
            .clone()
            .put(StoragePutArgs {
                entry: Some(StorageEntry {
                    key: key.to_string(),
                    value: value.to_vec(),
                    seal_wrap: false,
                }),
            })
            .await
            .map_err(|e| Error::Storage(e.to_string()))?
            .into_inner();

        if !resp.err.is_empty() {
            return Err(Error::Storage(resp.err));
        }

        Ok(())
    }

    /// Store a value in storage with seal-wrap enabled.
    pub async fn put_seal_wrapped(&self, key: &str, value: &[u8]) -> Result<(), Error> {
        let resp = self
            .client
            .clone()
            .put(StoragePutArgs {
                entry: Some(StorageEntry {
                    key: key.to_string(),
                    value: value.to_vec(),
                    seal_wrap: true,
                }),
            })
            .await
            .map_err(|e| Error::Storage(e.to_string()))?
            .into_inner();

        if !resp.err.is_empty() {
            return Err(Error::Storage(resp.err));
        }

        Ok(())
    }

    /// Delete a value from storage.
    pub async fn delete(&self, key: &str) -> Result<(), Error> {
        let resp = self
            .client
            .clone()
            .delete(StorageDeleteArgs {
                key: key.to_string(),
            })
            .await
            .map_err(|e| Error::Storage(e.to_string()))?
            .into_inner();

        if !resp.err.is_empty() {
            return Err(Error::Storage(resp.err));
        }

        Ok(())
    }

    /// List keys under a prefix.
    pub async fn list(&self, prefix: &str) -> Result<Vec<String>, Error> {
        let resp = self
            .client
            .clone()
            .list(StorageListArgs {
                prefix: prefix.to_string(),
            })
            .await
            .map_err(|e| Error::Storage(e.to_string()))?
            .into_inner();

        if !resp.err.is_empty() {
            return Err(Error::Storage(resp.err));
        }

        Ok(resp.keys)
    }

    /// Helper: get and deserialize JSON from storage.
    pub async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        key: &str,
    ) -> Result<Option<T>, Error> {
        match self.get(key).await? {
            Some(data) => {
                let value = serde_json::from_slice(&data)?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    /// Helper: serialize to JSON and store.
    pub async fn put_json<T: serde::Serialize>(&self, key: &str, value: &T) -> Result<(), Error> {
        let data = serde_json::to_vec(value)?;
        self.put(key, &data).await
    }

    /// Helper: serialize to JSON and store with seal-wrap.
    pub async fn put_json_sealed<T: serde::Serialize>(
        &self,
        key: &str,
        value: &T,
    ) -> Result<(), Error> {
        let data = serde_json::to_vec(value)?;
        self.put_seal_wrapped(key, &data).await
    }
}
