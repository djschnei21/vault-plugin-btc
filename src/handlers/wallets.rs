use super::validation::validate_json;
use crate::error::Error;
use crate::handlers::{empty_response, list_response, ok_response};
use crate::proto::pb::Response as PbResponse;
use crate::router::HandlerContext;
use crate::wallet::manager::WalletManager;
use crate::wallet::types::AddressType;
use serde::Deserialize;
use std::str::FromStr;
use tracing::{error, info};

#[derive(Deserialize)]
struct CreateWalletRequest {
    network: String,
    address_type: Option<String>,
    mnemonic: Option<String>,
}

/// POST /wallets/:name - Create a new wallet.
pub async fn create_wallet(ctx: HandlerContext) -> Result<PbResponse, Error> {
    let name = ctx
        .params
        .get("name")
        .ok_or_else(|| Error::InvalidRequest("missing wallet name".to_string()))?
        .clone();

    info!("Creating wallet: {}", name);

    let request: CreateWalletRequest = validate_json(&ctx.data)?;

    if !["mainnet", "testnet", "signet", "regtest"].contains(&request.network.as_str()) {
        error!("Invalid network for wallet {}: {}", name, request.network);
        return Err(Error::InvalidNetwork(request.network));
    }

    let network = match request.network.as_str() {
        "mainnet" => bitcoin::Network::Bitcoin,
        "testnet" => bitcoin::Network::Testnet,
        "signet" => bitcoin::Network::Signet,
        "regtest" => bitcoin::Network::Regtest,
        _ => return Err(Error::InvalidNetwork(request.network.clone())),
    };

    let address_type = if let Some(at_str) = &request.address_type {
        AddressType::from_str(at_str)
            .map_err(|_| Error::InvalidRequest(format!("invalid address_type: {at_str}")))
    } else {
        Ok(AddressType::default())
    }?;

    let mnemonic = request.mnemonic;

    let metadata = WalletManager::create_wallet(
        ctx.storage.clone(),
        &name,
        network,
        address_type,
        mnemonic.as_deref(),
    )
    .await?;

    info!("Wallet created successfully: {}", name);

    Ok(ok_response(serde_json::json!({
        "name": metadata.name,
        "network": metadata.network.to_string(),
        "address_type": metadata.address_type,
        "created_at": metadata.created_at
    })))
}

/// GET /wallets/:name - Read wallet public metadata.
pub async fn read_wallet(ctx: HandlerContext) -> Result<PbResponse, Error> {
    let name = ctx
        .params
        .get("name")
        .ok_or_else(|| Error::InvalidRequest("missing wallet name".to_string()))?;

    info!("Reading wallet: {}", name);

    let metadata = WalletManager::get_metadata(ctx.storage.clone(), name).await?;

    info!("Wallet read successfully: {}", name);

    Ok(ok_response(serde_json::json!({
        "name": metadata.name,
        "network": metadata.network.to_string(),
        "address_type": metadata.address_type,
        "created_at": metadata.created_at,
        "next_external_index": metadata.next_external_index,
        "next_internal_index": metadata.next_internal_index,
        "has_external_keychain": !metadata.external_descriptor_public.is_empty(),
        "has_internal_keychain": !metadata.internal_descriptor_public.is_empty(),
    })))
}

/// DELETE /wallets/:name - Delete a wallet.
pub async fn delete_wallet(ctx: HandlerContext) -> Result<PbResponse, Error> {
    let name = ctx
        .params
        .get("name")
        .ok_or_else(|| Error::InvalidRequest("missing wallet name".to_string()))?;

    info!("Deleting wallet: {}", name);

    WalletManager::delete_wallet(ctx.storage.clone(), name).await?;

    info!("Wallet deleted successfully: {}", name);

    Ok(empty_response())
}

/// LIST /wallets - List all wallet names.
pub async fn list_wallets(ctx: HandlerContext) -> Result<PbResponse, Error> {
    info!("Listing wallets");

    let names = WalletManager::list_wallets(ctx.storage.clone()).await?;

    info!("Listed {} wallets", names.len());

    Ok(list_response(names))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_json() {
        let invalid = serde_json::json!("invalid");
        let result = validate_json::<CreateWalletRequest>(&invalid);
        assert!(result.is_err());
    }
}
