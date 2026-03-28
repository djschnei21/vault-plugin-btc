use crate::error::Error;
use crate::handlers::ok_response;
use crate::proto::pb::Response as PbResponse;
use crate::router::HandlerContext;
use crate::wallet::manager::WalletManager;

/// GET /wallets/:name/keys - Get the extended public key (xpub) for the wallet.
pub async fn get_keys(ctx: HandlerContext) -> Result<PbResponse, Error> {
    let name = ctx
        .params
        .get("name")
        .ok_or_else(|| Error::InvalidRequest("missing wallet name".to_string()))?;

    let metadata = WalletManager::get_metadata(ctx.storage.clone(), name).await?;

    Ok(ok_response(serde_json::json!({
        "name": metadata.name,
        "network": metadata.network.to_string(),
        "external_descriptor": metadata.external_descriptor_public,
        "internal_descriptor": metadata.internal_descriptor_public,
    })))
}

fn parse_keychain(value: &str) -> Result<bdk_wallet::KeychainKind, Error> {
    match value {
        "external" => Ok(bdk_wallet::KeychainKind::External),
        "internal" | "change" => Ok(bdk_wallet::KeychainKind::Internal),
        other => Err(Error::InvalidRequest(format!("invalid keychain: {other}"))),
    }
}

fn parse_single_index(path_str: &str) -> Result<u32, Error> {
    if path_str.contains('/') {
        return Err(Error::InvalidRequest(
            "path must be a single unhardened index relative to the selected keychain".to_string(),
        ));
    }

    path_str
        .parse::<u32>()
        .map_err(|_| Error::InvalidRequest(format!("invalid derivation index: {path_str}")))
}

/// POST /wallets/:name/keys/derive - Derive a child public key at a specific path.
///
/// Request data:
/// - `path`: Single unhardened index (e.g., "5") relative to the keychain account key
/// - `keychain`: "external" (default) or "internal"
pub async fn derive_key(ctx: HandlerContext) -> Result<PbResponse, Error> {
    let name = ctx
        .params
        .get("name")
        .ok_or_else(|| Error::InvalidRequest("missing wallet name".to_string()))?;

    let path_str = ctx
        .data
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::InvalidRequest("missing 'path' parameter".to_string()))?;

    let keychain_value = ctx
        .data
        .get("keychain")
        .and_then(|v| v.as_str())
        .unwrap_or("external");

    let keychain_kind = parse_keychain(keychain_value)?;
    let index = parse_single_index(path_str)?;

    let (wallet, _) = WalletManager::load_bdk_wallet(ctx.storage.clone(), name).await?;

    let address = wallet.peek_address(keychain_kind, index);
    Ok(ok_response(serde_json::json!({
        "address": address.address.to_string(),
        "index": index,
        "keychain": keychain_value,
        "derivation_path": path_str,
    })))
}
