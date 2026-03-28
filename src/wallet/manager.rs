use crate::error::Error;
use crate::storage::Storage;
use crate::wallet::descriptors::{build_descriptors, to_public_descriptor};
use crate::wallet::types::{AddressType, WalletMetadata, WalletSecrets};
use bdk_wallet::Wallet;
use bip39::Mnemonic;
use bitcoin::bip32::Xpriv;
use bitcoin::Network;
use serde_json;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

/// Manages wallet lifecycle: create, load, delete.
/// Wallets are persisted in Vault's encrypted storage and reconstructed
/// on demand using BDK.
pub struct WalletManager;

impl WalletManager {
    /// Create a new wallet. If `mnemonic` is provided, use it; otherwise generate a new 24-word mnemonic.
    pub async fn create_wallet(
        storage: Arc<dyn Storage + Send + Sync>,
        name: &str,
        network: Network,
        address_type: AddressType,
        mnemonic_phrase: Option<&str>,
    ) -> Result<WalletMetadata, Error> {
        // Check if wallet already exists
        let meta_key = format!("wallets/{}/metadata", name);
        if storage.get(&meta_key).await?.is_some() {
            return Err(Error::WalletAlreadyExists(name.to_string()));
        }

        // Generate or parse mnemonic
        let mnemonic = match mnemonic_phrase {
            Some(phrase) => {
                Mnemonic::from_str(phrase).map_err(|e| Error::InvalidMnemonic(e.to_string()))?
            }
            None => Mnemonic::generate(24).map_err(|e| Error::InvalidMnemonic(e.to_string()))?,
        };

        // Derive master key
        let seed = mnemonic.to_seed("");
        let xprv = Xpriv::new_master(network, &seed)
            .map_err(|e| Error::Internal(format!("failed to derive master key: {e}")))?;

        // Build descriptors
        let (ext_desc, int_desc) = build_descriptors(&xprv, address_type, network)?;

        // Derive public descriptors
        let ext_pub = to_public_descriptor(&ext_desc)?;
        let int_pub = to_public_descriptor(&int_desc)?;

        // Store secrets (seal-wrapped)
        let secrets = WalletSecrets {
            mnemonic: Some(mnemonic.to_string()),
            external_descriptor_private: ext_desc,
            internal_descriptor_private: int_desc,
        };
        let secrets_key = format!("wallets/{}/secrets", name);
        let secrets_data = serde_json::to_vec(&secrets)?;
        storage
            .put_sealed(&secrets_key, secrets_data)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;

        // Store metadata
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let metadata = WalletMetadata {
            name: name.to_string(),
            network,
            address_type,
            created_at: now,
            external_descriptor_public: ext_pub,
            internal_descriptor_public: int_pub,
            next_external_index: 0,
            next_internal_index: 0,
        };
        let metadata_data = serde_json::to_vec(&metadata)?;
        storage
            .put(&meta_key, metadata_data)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;

        info!(wallet = name, "wallet created");

        Ok(metadata)
    }

    /// Load wallet metadata from storage.
    pub async fn get_metadata(
        storage: Arc<dyn Storage + Send + Sync>,
        name: &str,
    ) -> Result<WalletMetadata, Error> {
        let key = format!("wallets/{}/metadata", name);
        let data = storage
            .get(&key)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;
        match data {
            Some(d) => {
                let value: WalletMetadata = serde_json::from_slice(&d).map_err(Error::Serde)?;
                Ok(value)
            }
            None => Err(Error::WalletNotFound(name.to_string())),
        }
    }

    /// Load wallet secrets from storage.
    pub async fn get_secrets(
        storage: Arc<dyn Storage + Send + Sync>,
        name: &str,
    ) -> Result<WalletSecrets, Box<dyn std::error::Error>> {
        let key = format!("wallets/{}/secrets", name);
        let data = storage
            .get(&key)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;
        match data {
            Some(d) => {
                let value: WalletSecrets = serde_json::from_slice(&d).map_err(Error::Serde)?;
                Ok(value)
            }
            None => Err(Box::new(Error::WalletNotFound(name.to_string()))),
        }
    }

    /// Reconstruct a BDK Wallet from stored descriptors for signing/address operations.
    pub async fn load_bdk_wallet(
        storage: Arc<dyn Storage + Send + Sync>,
        name: &str,
    ) -> Result<(Wallet, WalletMetadata), Box<dyn std::error::Error>> {
        let metadata = Self::get_metadata(storage.clone(), name).await?;
        let secrets = Self::get_secrets(storage, name).await?;

        // Clone descriptor strings before dropping secrets (ZeroizeOnDrop)
        let ext_desc = secrets.external_descriptor_private.clone();
        let int_desc = secrets.internal_descriptor_private.clone();
        drop(secrets);

        let wallet = Wallet::create(ext_desc, int_desc)
            .network(metadata.network)
            .create_wallet_no_persist()
            .map_err(|e| Error::Internal(format!("failed to create BDK wallet: {e}")))?;

        Ok((wallet, metadata))
    }

    /// Update wallet metadata in storage (e.g., after advancing derivation index).
    pub async fn update_metadata(
        storage: Arc<dyn Storage + Send + Sync>,
        metadata: &WalletMetadata,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = format!("wallets/{}/metadata", metadata.name);
        let data = serde_json::to_vec(metadata).map_err(Error::Serde)?;
        Ok(storage
            .put(&key, data)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?)
    }

    /// Delete a wallet and all associated data.
    pub async fn delete_wallet(
        storage: Arc<dyn Storage + Send + Sync>,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Check it exists first
        Self::get_metadata(storage.clone(), name).await?;

        // Delete all keys under this wallet
        let prefix = format!("wallets/{}/", name);
        let keys = storage
            .list(&prefix)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;
        for key in keys {
            let full_key = format!("{}{}", prefix, key);
            storage
                .delete(&full_key)
                .await
                .map_err(|e| Error::Storage(e.to_string()))?;
        }

        info!(wallet = name, "wallet deleted");
        Ok(())
    }

    /// List all wallet names.
    pub async fn list_wallets(
        storage: Arc<dyn Storage + Send + Sync>,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let keys = storage
            .list("wallets/")
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;
        // Keys returned by vault list are the immediate children under the prefix.
        // For "wallets/", we get entries like "my-wallet/" - strip the trailing slash.
        let names: Vec<String> = keys
            .into_iter()
            .filter_map(|k| {
                let trimmed = k.trim_end_matches('/');
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            })
            .collect();
        Ok(names)
    }

    /// Advance the derivation index and return the next external address.
    /// This operation is serialized per-wallet to prevent address reuse.
    pub async fn next_external_address(
        storage: Arc<dyn Storage + Send + Sync>,
        name: &str,
    ) -> Result<(String, u32), Box<dyn std::error::Error>> {
        let wallet_lock = crate::wallet::locks::wallet_lock(name).await;
        let _guard = wallet_lock.lock().await;

        let mut metadata = Self::get_metadata(storage.clone(), name).await?;
        let (wallet, _) = Self::load_bdk_wallet(storage.clone(), name).await?;
        let index = metadata.next_external_index;
        let address = wallet
            .peek_address(bdk_wallet::KeychainKind::External, index)
            .address
            .to_string();

        metadata.next_external_index = index + 1;
        Self::update_metadata(storage, &metadata).await?;

        Ok((address, index))
    }
}
