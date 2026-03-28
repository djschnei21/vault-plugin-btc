use crate::error::Error;
use serde::de::DeserializeOwned;

pub fn validate_json<T: DeserializeOwned>(value: &serde_json::Value) -> Result<T, Error> {
    serde_json::from_value(value.clone())
        .map_err(|e| Error::InvalidRequest(format!("Invalid JSON: {}", e)))
}

pub fn parse_network(network: &str) -> Result<bitcoin::Network, Error> {
    match network {
        "mainnet" => Ok(bitcoin::Network::Bitcoin),
        "testnet" => Ok(bitcoin::Network::Testnet),
        "signet" => Ok(bitcoin::Network::Signet),
        "regtest" => Ok(bitcoin::Network::Regtest),
        _ => Err(Error::InvalidNetwork(network.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct TestStruct {
        name: String,
    }

    #[test]
    fn test_valid_json() {
        let value = serde_json::json!({"name": "test"});
        let result: Result<TestStruct, _> = validate_json(&value);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().name, "test");
    }

    #[test]
    fn test_invalid_json() {
        let value = serde_json::json!("invalid");
        let result: Result<TestStruct, _> = validate_json(&value);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_network_accepts_supported_values() {
        assert_eq!(parse_network("mainnet").unwrap(), bitcoin::Network::Bitcoin);
        assert_eq!(parse_network("testnet").unwrap(), bitcoin::Network::Testnet);
        assert_eq!(parse_network("signet").unwrap(), bitcoin::Network::Signet);
        assert_eq!(parse_network("regtest").unwrap(), bitcoin::Network::Regtest);
    }

    #[test]
    fn test_parse_network_rejects_invalid_values() {
        let result = parse_network("invalid-network");
        assert!(matches!(
            result,
            Err(Error::InvalidNetwork(network)) if network == "invalid-network"
        ));
    }
}
