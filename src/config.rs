use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    #[serde(default = "default_network")]
    pub network: String,
    pub blockchain_backend_url: Option<String>,
}

fn default_network() -> String {
    "testnet".to_string()
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            network: default_network(),
            blockchain_backend_url: None,
        }
    }
}

impl PluginConfig {
    pub fn validate(&self) -> Result<(), crate::error::Error> {
        if self.network.is_empty() {
            return Err(crate::error::Error::ConfigError(
                "network required".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let config = PluginConfig {
            network: "".to_string(),
            blockchain_backend_url: None,
        };
        assert!(config.validate().is_err());
    }
}
