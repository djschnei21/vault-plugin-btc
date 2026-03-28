use bitcoin::Network;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    #[serde(default = "default_network")]
    pub network: Network,
    pub blockchain_backend_url: Option<String>,
}

fn default_network() -> Network {
    Network::Testnet
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            network: default_network(),
            blockchain_backend_url: None,
        }
    }
}
