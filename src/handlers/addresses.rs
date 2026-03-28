use crate::error::Error;
use crate::handlers::ok_response;
use crate::proto::pb::Response as PbResponse;
use crate::router::HandlerContext;
use crate::wallet::manager::WalletManager;
use bdk_wallet::KeychainKind;

/// POST /wallets/:name/addresses/new - Generate the next receiving address.
///
/// Advances the external derivation index and returns the new address.
pub async fn new_address(ctx: HandlerContext) -> Result<PbResponse, Error> {
    let name = ctx
        .params
        .get("name")
        .ok_or_else(|| Error::InvalidRequest("missing wallet name".to_string()))?;

    let (address, index) = WalletManager::next_external_address(ctx.storage.clone(), name)
        .await
        .map_err(|e| Error::Internal(format!("failed to allocate address: {e}")))?;

    Ok(ok_response(serde_json::json!({
        "address": address,
        "index": index,
        "keychain": "external",
    })))
}

/// GET /wallets/:name/addresses - List all generated addresses.
///
/// Returns all addresses from index 0 up to the current derivation index.
pub async fn list_addresses(ctx: HandlerContext) -> Result<PbResponse, Error> {
    let name = ctx
        .params
        .get("name")
        .ok_or_else(|| Error::InvalidRequest("missing wallet name".to_string()))?;

    let metadata = WalletManager::get_metadata(ctx.storage.clone(), name).await?;

    if metadata.next_external_index == 0 {
        return Ok(ok_response(serde_json::json!({
            "addresses": [],
            "count": 0,
        })));
    }

    let (wallet, _) = WalletManager::load_bdk_wallet(ctx.storage.clone(), name).await?;

    let mut addresses = Vec::new();
    for i in 0..metadata.next_external_index {
        let addr_info = wallet.peek_address(KeychainKind::External, i);
        addresses.push(serde_json::json!({
            "address": addr_info.address.to_string(),
            "index": i,
        }));
    }

    Ok(ok_response(serde_json::json!({
        "addresses": addresses,
        "count": addresses.len(),
    })))
}
