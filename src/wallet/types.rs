use bitcoin::Network;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Address type determines the descriptor template and derivation path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AddressType {
    Legacy,
    NestedSegwit,
    #[default]
    NativeSegwit,
    Taproot,
}

impl AddressType {
    /// BIP purpose number for this address type.
    pub fn purpose(&self) -> u32 {
        match self {
            AddressType::Legacy => 44,
            AddressType::NestedSegwit => 49,
            AddressType::NativeSegwit => 84,
            AddressType::Taproot => 86,
        }
    }
}

impl FromStr for AddressType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "legacy" | "p2pkh" => Ok(AddressType::Legacy),
            "nested_segwit" | "nested-segwit" | "p2sh-p2wpkh" => Ok(AddressType::NestedSegwit),
            "native_segwit" | "native-segwit" | "p2wpkh" | "segwit" => {
                Ok(AddressType::NativeSegwit)
            }
            "taproot" | "p2tr" => Ok(AddressType::Taproot),
            _ => Err(()),
        }
    }
}

/// Public wallet metadata stored at `wallets/{name}/metadata`.
/// Never contains private keys or mnemonics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletMetadata {
    pub name: String,
    pub network: Network,
    pub address_type: AddressType,
    pub created_at: u64,
    pub external_descriptor_public: String,
    pub internal_descriptor_public: String,
    pub next_external_index: u32,
    pub next_internal_index: u32,
}

/// Sensitive wallet data stored at `wallets/{name}/secrets` with seal-wrap.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct WalletSecrets {
    pub mnemonic: Option<String>,
    pub external_descriptor_private: String,
    pub internal_descriptor_private: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_type_from_str() {
        assert_eq!(
            "legacy".parse::<AddressType>().ok(),
            Some(AddressType::Legacy)
        );
        assert_eq!(
            "p2pkh".parse::<AddressType>().ok(),
            Some(AddressType::Legacy)
        );
        assert_eq!(
            "segwit".parse::<AddressType>().ok(),
            Some(AddressType::NativeSegwit)
        );
        assert_eq!(
            "native-segwit".parse::<AddressType>().ok(),
            Some(AddressType::NativeSegwit)
        );
        assert_eq!(
            "p2wpkh".parse::<AddressType>().ok(),
            Some(AddressType::NativeSegwit)
        );
        assert_eq!(
            "nested-segwit".parse::<AddressType>().ok(),
            Some(AddressType::NestedSegwit)
        );
        assert_eq!(
            "taproot".parse::<AddressType>().ok(),
            Some(AddressType::Taproot)
        );
        assert_eq!(
            "p2tr".parse::<AddressType>().ok(),
            Some(AddressType::Taproot)
        );
        assert!("invalid".parse::<AddressType>().is_err());
    }

    #[test]
    fn test_address_type_purpose() {
        assert_eq!(AddressType::Legacy.purpose(), 44);
        assert_eq!(AddressType::NestedSegwit.purpose(), 49);
        assert_eq!(AddressType::NativeSegwit.purpose(), 84);
        assert_eq!(AddressType::Taproot.purpose(), 86);
    }

    #[test]
    fn test_address_type_default() {
        assert_eq!(AddressType::default(), AddressType::NativeSegwit);
    }

    #[test]
    fn test_wallet_metadata_serialization() {
        let meta = WalletMetadata {
            name: "test".to_string(),
            network: bitcoin::Network::Testnet,
            address_type: AddressType::NativeSegwit,
            created_at: 1234567890,
            external_descriptor_public: "wpkh(tpub...)".to_string(),
            internal_descriptor_public: "wpkh(tpub...)".to_string(),
            next_external_index: 5,
            next_internal_index: 2,
        };

        let json = serde_json::to_string(&meta).unwrap();
        let deserialized: WalletMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "test");
        assert_eq!(deserialized.next_external_index, 5);
    }

    #[test]
    fn test_wallet_secrets_zeroize() {
        let secrets = WalletSecrets {
            mnemonic: Some("test mnemonic".to_string()),
            external_descriptor_private: "wpkh(tprv...)".to_string(),
            internal_descriptor_private: "wpkh(tprv...)".to_string(),
        };
        // Verify the struct can be serialized/deserialized
        let json = serde_json::to_string(&secrets).unwrap();
        let deserialized: WalletSecrets = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.mnemonic, Some("test mnemonic".to_string()));
        // ZeroizeOnDrop will clear memory when `secrets` goes out of scope
    }
}
