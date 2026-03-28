use crate::error::Error;
use crate::handlers::ok_response;
use crate::proto::pb::Response as PbResponse;
use crate::router::HandlerContext;
use crate::wallet::manager::WalletManager;
use bitcoin::bip32::{ChildNumber, DerivationPath};
use std::str::FromStr;

/// GET /wallets/:name/keys - Get the extended public key (xpub) for the wallet.
pub async fn get_keys(ctx: HandlerContext) -> Result<PbResponse, Error> {
    let name = ctx
        .params
        .get("name")
        .ok_or_else(|| Error::InvalidRequest("missing wallet name".to_string()))?;

    let metadata = WalletManager::get_metadata(&ctx.storage, name).await?;

    Ok(ok_response(serde_json::json!({
        "name": metadata.name,
        "network": metadata.network.to_string(),
        "external_descriptor": metadata.external_descriptor_public,
        "internal_descriptor": metadata.internal_descriptor_public,
    })))
}

/// POST /wallets/:name/keys/derive - Derive a child public key at a specific path.
///
/// Request data:
/// - `path`: BIP32 derivation path (e.g., "m/0/5" or "0/5") relative to the account key
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

    let keychain = ctx
        .data
        .get("keychain")
        .and_then(|v| v.as_str())
        .unwrap_or("external");

    let (wallet, metadata) = WalletManager::load_bdk_wallet(&ctx.storage, name).await?;

    // Get the appropriate descriptor's public key
    let descriptor = match keychain {
        "internal" | "change" => &metadata.internal_descriptor_public,
        _ => &metadata.external_descriptor_public,
    };

    // Parse the derivation path
    let derivation: Vec<ChildNumber> = if path_str.starts_with("m/") || path_str.starts_with("M/")
    {
        let dp = DerivationPath::from_str(path_str)
            .map_err(|e| Error::InvalidRequest(format!("invalid derivation path: {e}")))?;
        dp.into_iter().copied().collect()
    } else {
        // Parse as relative path segments
        path_str
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|s| {
                if let Some(stripped) = s.strip_suffix('\'').or(s.strip_suffix('h')) {
                    let idx: u32 = stripped
                        .parse()
                        .map_err(|_| Error::InvalidRequest(format!("invalid path segment: {s}")))?;
                    Ok(ChildNumber::from_hardened_idx(idx)
                        .map_err(|e| Error::InvalidRequest(e.to_string()))?)
                } else {
                    let idx: u32 = s
                        .parse()
                        .map_err(|_| Error::InvalidRequest(format!("invalid path segment: {s}")))?;
                    Ok(ChildNumber::from_normal_idx(idx)
                        .map_err(|e| Error::InvalidRequest(e.to_string()))?)
                }
            })
            .collect::<Result<Vec<_>, Error>>()?
    };

    // Use the BDK wallet to peek at the address for a specific index
    // For simple index derivation, we can use peek_address
    if derivation.len() == 1 {
        if let ChildNumber::Normal { index } = derivation[0] {
            let keychain_kind = match keychain {
                "internal" | "change" => bdk_wallet::KeychainKind::Internal,
                _ => bdk_wallet::KeychainKind::External,
            };

            let address = wallet.peek_address(keychain_kind, index);
            return Ok(ok_response(serde_json::json!({
                "address": address.address.to_string(),
                "index": index,
                "keychain": keychain,
                "derivation_path": path_str,
            })));
        }
    }

    Ok(ok_response(serde_json::json!({
        "descriptor": descriptor,
        "derivation_path": path_str,
        "keychain": keychain,
    })))
}
