use crate::error::Error;
use crate::storage::Storage;
use rand::random;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const RESERVATION_TTL_SECS: u64 = 5;
const RESERVATION_RETRY_DELAY_MS: u64 = 25;
const RESERVATION_MAX_RETRIES: usize = 3;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AddressReservation {
    pub index: u32,
    pub holder: String,
    pub created_at: u64,
}

impl AddressReservation {
    pub fn new(index: u32) -> Self {
        Self {
            index,
            holder: format!("{}-{}", std::process::id(), random::<u64>()),
            created_at: now_secs(),
        }
    }

    pub fn is_stale(&self) -> bool {
        now_secs().saturating_sub(self.created_at) > RESERVATION_TTL_SECS
    }

    pub fn retry_delay() -> std::time::Duration {
        std::time::Duration::from_millis(RESERVATION_RETRY_DELAY_MS)
    }

    pub fn max_retries() -> usize {
        RESERVATION_MAX_RETRIES
    }

    pub fn key(name: &str) -> String {
        format!("wallets/{name}/address-reservation")
    }

    pub async fn load(
        storage: Arc<dyn Storage + Send + Sync>,
        name: &str,
    ) -> Result<Option<Self>, Error> {
        let key = Self::key(name);
        let data = storage
            .get(&key)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;

        data.map(|bytes| serde_json::from_slice(&bytes).map_err(Error::Serde))
            .transpose()
    }

    pub async fn store(
        &self,
        storage: Arc<dyn Storage + Send + Sync>,
        name: &str,
    ) -> Result<(), Error> {
        let key = Self::key(name);
        let data = serde_json::to_vec(self)?;
        storage
            .put(&key, data)
            .await
            .map_err(|e| Error::Storage(e.to_string()))
    }

    pub async fn clear(
        storage: Arc<dyn Storage + Send + Sync>,
        name: &str,
    ) -> Result<(), Error> {
        let key = Self::key(name);
        storage
            .delete(&key)
            .await
            .map_err(|e| Error::Storage(e.to_string()))
    }

    pub async fn clear_if_owned(
        &self,
        storage: Arc<dyn Storage + Send + Sync>,
        name: &str,
    ) -> Result<(), Error> {
        if self.is_owned_by(storage.clone(), name).await? {
            Self::clear(storage, name).await?;
        }

        Ok(())
    }

    pub async fn is_owned_by(
        &self,
        storage: Arc<dyn Storage + Send + Sync>,
        name: &str,
    ) -> Result<bool, Error> {
        Ok(Self::load(storage, name).await?.as_ref() == Some(self))
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
