use crate::config::PluginConfig;
use crate::error::Error;
use crate::handlers::ok_response;
use crate::proto::pb::Response as PbResponse;
use crate::router::HandlerContext;

const CONFIG_KEY: &str = "config/plugin";

/// GET /config - Read the current plugin configuration.
pub async fn read_config(ctx: HandlerContext) -> Result<PbResponse, Error> {
    let data = ctx
        .storage
        .get(CONFIG_KEY)
        .await
        .map_err(|e| Error::Storage(e.to_string()))?;
    let config: PluginConfig = match data {
        Some(d) => serde_json::from_slice(&d).map_err(|e| Error::Serde(e))?,
        None => PluginConfig::default(),
    };
    Ok(ok_response(serde_json::to_value(&config)?))
}

/// POST /config - Set the plugin configuration.
pub async fn write_config(ctx: HandlerContext) -> Result<PbResponse, Error> {
    let data = ctx
        .storage
        .get(CONFIG_KEY)
        .await
        .map_err(|e| Error::Storage(e.to_string()))?;
    let mut config: PluginConfig = match data {
        Some(d) => serde_json::from_slice(&d).map_err(|e| Error::Serde(e))?,
        None => PluginConfig::default(),
    };

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

    let config_data = serde_json::to_vec(&config).map_err(|e| Error::Serde(e))?;
    ctx.storage.put(CONFIG_KEY, config_data).await.map_err(|e| Error::Storage(e.to_string()))?;

    Ok(ok_response(serde_json::to_value(&config)?))
}
