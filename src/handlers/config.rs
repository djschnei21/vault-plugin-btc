use crate::config::PluginConfig;
use crate::error::Error;
use crate::handlers::ok_response;
use crate::proto::pb::Response as PbResponse;
use crate::router::HandlerContext;

const CONFIG_KEY: &str = "config/plugin";

/// GET /config - Read the current plugin configuration.
pub async fn read_config(ctx: HandlerContext) -> Result<PbResponse, Error> {
    let config: PluginConfig = ctx
        .storage
        .get_json(CONFIG_KEY)
        .await?
        .unwrap_or_default();

    Ok(ok_response(serde_json::to_value(&config)?))
}

/// POST /config - Set the plugin configuration.
pub async fn write_config(ctx: HandlerContext) -> Result<PbResponse, Error> {
    let mut config: PluginConfig = ctx
        .storage
        .get_json(CONFIG_KEY)
        .await?
        .unwrap_or_default();

    // Update fields from request data
    if let Some(network) = ctx.data.get("network").and_then(|v| v.as_str()) {
        config.network = network
            .parse()
            .map_err(|_| Error::InvalidRequest(format!("invalid network: {network}")))?;
    }

    if let Some(url) = ctx.data.get("blockchain_backend_url").and_then(|v| v.as_str()) {
        if url.is_empty() {
            config.blockchain_backend_url = None;
        } else {
            config.blockchain_backend_url = Some(url.to_string());
        }
    }

    ctx.storage.put_json(CONFIG_KEY, &config).await?;

    Ok(ok_response(serde_json::to_value(&config)?))
}
