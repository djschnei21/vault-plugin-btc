use super::validation::{parse_network, validate_json};
use crate::config::PluginConfig;
use crate::error::Error;
use crate::handlers::ok_response;
use crate::proto::pb::Response as PbResponse;
use crate::router::HandlerContext;
use serde::Deserialize;
use tracing::{error, info};

const CONFIG_KEY: &str = "config/plugin";

#[derive(Deserialize)]
struct WriteConfigRequest {
    network: Option<String>,
    blockchain_backend_url: Option<String>,
}

/// GET /config - Read the current plugin configuration.
pub async fn read_config(ctx: HandlerContext) -> Result<PbResponse, Error> {
    info!(key = CONFIG_KEY, "Reading plugin config");

    let data = ctx
        .storage
        .get(CONFIG_KEY)
        .await
        .map_err(|e| Error::Storage(e.to_string()))?;
    let config: PluginConfig = match data {
        Some(d) => serde_json::from_slice(&d).map_err(Error::Serde)?,
        None => PluginConfig::default(),
    };

    info!(key = CONFIG_KEY, "Plugin config read successfully");

    Ok(ok_response(serde_json::to_value(&config)?))
}

/// POST /config - Set the plugin configuration.
pub async fn write_config(ctx: HandlerContext) -> Result<PbResponse, Error> {
    info!(key = CONFIG_KEY, "Writing plugin config");

    let data = ctx
        .storage
        .get(CONFIG_KEY)
        .await
        .map_err(|e| Error::Storage(e.to_string()))?;
    let mut config: PluginConfig = match data {
        Some(d) => serde_json::from_slice(&d).map_err(Error::Serde)?,
        None => PluginConfig::default(),
    };

    let request: WriteConfigRequest = validate_json(&ctx.data)?;

    // Update fields from request data
    if let Some(network) = request.network {
        if let Err(err) = parse_network(&network) {
            error!(network = %network, "Invalid network for plugin config write");
            return Err(err);
        }

        config.network = network;
    }

    if let Some(url) = request.blockchain_backend_url {
        if url.is_empty() {
            config.blockchain_backend_url = None;
        } else {
            config.blockchain_backend_url = Some(url);
        }
    }

    let config_data = serde_json::to_vec(&config).map_err(Error::Serde)?;
    ctx.storage
        .put(CONFIG_KEY, config_data)
        .await
        .map_err(|e| Error::Storage(e.to_string()))?;

    info!(key = CONFIG_KEY, "Plugin config written successfully");

    Ok(ok_response(serde_json::to_value(&config)?))
}
