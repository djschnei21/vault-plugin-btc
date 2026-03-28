use crate::config::PluginConfig;
use crate::error::Error;
use crate::handlers::{empty_response, list_response, ok_response};
use crate::proto::pb::Response as PbResponse;
use crate::router::HandlerContext;
use crate::wallet::manager::WalletManager;
use crate::wallet::types::AddressType;

/// POST /wallets/:name - Create a new wallet.
pub async fn create_wallet(ctx: HandlerContext) -> Result<PbResponse, Error> {
    let name = ctx
        .params
        .get("name")
        .ok_or_else(|| Error::InvalidRequest("missing wallet name".to_string()))?
        .clone();

    // Get network from request or fall back to plugin config
    let network = if let Some(net_str) = ctx.data.get("network").and_then(|v| v.as_str()) {
        net_str
            .parse()
            .map_err(|_| Error::InvalidRequest(format!("invalid network: {net_str}")))?
    } else {
        let config: PluginConfig = ctx
            .storage
            .get_json("config/plugin")
            .await?
            .unwrap_or_default();
        config.network
    };

    // Get address type
    let address_type = if let Some(at_str) = ctx.data.get("address_type").and_then(|v| v.as_str())
    {
        AddressType::from_str(at_str)
            .ok_or_else(|| Error::InvalidRequest(format!("invalid address_type: {at_str}")))?
    } else {
        AddressType::default()
    };

    // Optional mnemonic import
    let mnemonic = ctx
        .data
        .get("mnemonic")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let metadata = WalletManager::create_wallet(
        &ctx.storage,
        &name,
        network,
        address_type,
        mnemonic.as_deref(),
    )
    .await?;

    // Return public metadata only (never expose mnemonic or private descriptors)
    Ok(ok_response(serde_json::json!({
        "name": metadata.name,
        "network": metadata.network.to_string(),
        "address_type": metadata.address_type,
        "created_at": metadata.created_at,
        "external_descriptor": metadata.external_descriptor_public,
        "internal_descriptor": metadata.internal_descriptor_public,
    })))
}

/// GET /wallets/:name - Read wallet public metadata.
pub async fn read_wallet(ctx: HandlerContext) -> Result<PbResponse, Error> {
    let name = ctx
        .params
        .get("name")
        .ok_or_else(|| Error::InvalidRequest("missing wallet name".to_string()))?;

    let metadata = WalletManager::get_metadata(&ctx.storage, name).await?;

    Ok(ok_response(serde_json::json!({
        "name": metadata.name,
        "network": metadata.network.to_string(),
        "address_type": metadata.address_type,
        "created_at": metadata.created_at,
        "external_descriptor": metadata.external_descriptor_public,
        "internal_descriptor": metadata.internal_descriptor_public,
        "next_external_index": metadata.next_external_index,
        "next_internal_index": metadata.next_internal_index,
    })))
}

/// DELETE /wallets/:name - Delete a wallet.
pub async fn delete_wallet(ctx: HandlerContext) -> Result<PbResponse, Error> {
    let name = ctx
        .params
        .get("name")
        .ok_or_else(|| Error::InvalidRequest("missing wallet name".to_string()))?;

    WalletManager::delete_wallet(&ctx.storage, name).await?;

    Ok(empty_response())
}

/// LIST /wallets - List all wallet names.
pub async fn list_wallets(ctx: HandlerContext) -> Result<PbResponse, Error> {
    let names = WalletManager::list_wallets(&ctx.storage).await?;
    Ok(list_response(names))
}
