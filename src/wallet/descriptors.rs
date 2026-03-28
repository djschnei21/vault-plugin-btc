use crate::error::Error;
use crate::wallet::types::AddressType;
use bitcoin::bip32::Xpriv;
use bitcoin::Network;

/// Build descriptor strings for the external (receiving) and internal (change) keychains.
///
/// Uses standard BIP derivation paths:
/// - Legacy (BIP44): pkh(xprv/44h/coin_type/0h/0/*)
/// - Nested Segwit (BIP49): sh(wpkh(xprv/49h/coin_type/0h/0/*))
/// - Native Segwit (BIP84): wpkh(xprv/84h/coin_type/0h/0/*)
/// - Taproot (BIP86): tr(xprv/86h/coin_type/0h/0/*)
pub fn build_descriptors(
    xprv: &Xpriv,
    address_type: AddressType,
    network: Network,
) -> Result<(String, String), Error> {
    let coin_type = match network {
        Network::Bitcoin => 0,
        _ => 1,
    };
    let purpose = address_type.purpose();

    let (external, internal) = match address_type {
        AddressType::Legacy => (
            format!("pkh({}/{}h/{}h/0h/0/*)", xprv, purpose, coin_type),
            format!("pkh({}/{}h/{}h/0h/1/*)", xprv, purpose, coin_type),
        ),
        AddressType::NestedSegwit => (
            format!("sh(wpkh({}/{}h/{}h/0h/0/*))", xprv, purpose, coin_type),
            format!("sh(wpkh({}/{}h/{}h/0h/1/*))", xprv, purpose, coin_type),
        ),
        AddressType::NativeSegwit => (
            format!("wpkh({}/{}h/{}h/0h/0/*)", xprv, purpose, coin_type),
            format!("wpkh({}/{}h/{}h/0h/1/*)", xprv, purpose, coin_type),
        ),
        AddressType::Taproot => (
            format!("tr({}/{}h/{}h/0h/0/*)", xprv, purpose, coin_type),
            format!("tr({}/{}h/{}h/0h/1/*)", xprv, purpose, coin_type),
        ),
    };

    Ok((external, internal))
}

/// Convert a private descriptor string to a public-only descriptor.
/// Replaces xprv-based keys with their xpub equivalent by parsing
/// through BDK's descriptor infrastructure.
pub fn to_public_descriptor(private_desc: &str) -> Result<String, Error> {
    use miniscript::descriptor::{Descriptor, DescriptorPublicKey};

    // Parse the private descriptor, extracting public keys
    let (desc, _keymap) =
        Descriptor::<DescriptorPublicKey>::parse_descriptor(&bitcoin::secp256k1::Secp256k1::new(), private_desc)
            .map_err(|e| Error::InvalidDescriptor(e.to_string()))?;

    Ok(desc.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Mnemonic;
    use std::str::FromStr;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_xprv(network: Network) -> Xpriv {
        let mnemonic = Mnemonic::from_str(TEST_MNEMONIC).unwrap();
        let seed = mnemonic.to_seed("");
        Xpriv::new_master(network, &seed).unwrap()
    }

    #[test]
    fn test_build_native_segwit_testnet() {
        let xprv = test_xprv(Network::Testnet);
        let (ext, int) = build_descriptors(&xprv, AddressType::NativeSegwit, Network::Testnet).unwrap();
        assert!(ext.starts_with("wpkh("));
        assert!(ext.contains("/84h/1h/0h/0/*"));
        assert!(int.contains("/84h/1h/0h/1/*"));
    }

    #[test]
    fn test_build_taproot_mainnet() {
        let xprv = test_xprv(Network::Bitcoin);
        let (ext, int) = build_descriptors(&xprv, AddressType::Taproot, Network::Bitcoin).unwrap();
        assert!(ext.starts_with("tr("));
        assert!(ext.contains("/86h/0h/0h/0/*"));
        assert!(int.contains("/86h/0h/0h/1/*"));
    }

    #[test]
    fn test_build_legacy_testnet() {
        let xprv = test_xprv(Network::Testnet);
        let (ext, _) = build_descriptors(&xprv, AddressType::Legacy, Network::Testnet).unwrap();
        assert!(ext.starts_with("pkh("));
        assert!(ext.contains("/44h/1h/0h/0/*"));
    }

    #[test]
    fn test_build_nested_segwit() {
        let xprv = test_xprv(Network::Testnet);
        let (ext, _) = build_descriptors(&xprv, AddressType::NestedSegwit, Network::Testnet).unwrap();
        assert!(ext.starts_with("sh(wpkh("));
        assert!(ext.contains("/49h/1h/0h/0/*"));
    }

    #[test]
    fn test_to_public_descriptor() {
        let xprv = test_xprv(Network::Testnet);
        let (ext_priv, _) = build_descriptors(&xprv, AddressType::NativeSegwit, Network::Testnet).unwrap();
        let ext_pub = to_public_descriptor(&ext_priv).unwrap();
        // Public descriptor should not contain xprv
        assert!(!ext_pub.contains("tprv"), "public descriptor should not contain private key");
        assert!(ext_pub.starts_with("wpkh("));
        // Should contain tpub (testnet xpub)
        assert!(ext_pub.contains("tpub"), "public descriptor should contain tpub");
    }

    #[test]
    fn test_descriptors_valid_for_bdk() {
        let xprv = test_xprv(Network::Testnet);
        for addr_type in [AddressType::Legacy, AddressType::NestedSegwit, AddressType::NativeSegwit, AddressType::Taproot] {
            let (ext, int) = build_descriptors(&xprv, addr_type, Network::Testnet).unwrap();

            // Should be able to create a BDK wallet from these descriptors
            let wallet = bdk_wallet::Wallet::create(ext, int)
                .network(Network::Testnet)
                .create_wallet_no_persist();
            assert!(wallet.is_ok(), "BDK wallet creation failed for {:?}: {:?}", addr_type, wallet.err());
        }
    }

    #[test]
    fn test_address_generation_from_descriptors() {
        let xprv = test_xprv(Network::Testnet);
        let (ext, int) = build_descriptors(&xprv, AddressType::NativeSegwit, Network::Testnet).unwrap();

        let wallet = bdk_wallet::Wallet::create(ext, int)
            .network(Network::Testnet)
            .create_wallet_no_persist()
            .unwrap();

        let addr = wallet.peek_address(bdk_wallet::KeychainKind::External, 0);
        let addr_str = addr.address.to_string();
        // Testnet native segwit addresses start with "tb1q"
        assert!(addr_str.starts_with("tb1q"), "expected tb1q address, got {}", addr_str);
    }

    #[test]
    fn test_taproot_address_generation() {
        let xprv = test_xprv(Network::Testnet);
        let (ext, int) = build_descriptors(&xprv, AddressType::Taproot, Network::Testnet).unwrap();

        let wallet = bdk_wallet::Wallet::create(ext, int)
            .network(Network::Testnet)
            .create_wallet_no_persist()
            .unwrap();

        let addr = wallet.peek_address(bdk_wallet::KeychainKind::External, 0);
        let addr_str = addr.address.to_string();
        // Testnet taproot addresses start with "tb1p"
        assert!(addr_str.starts_with("tb1p"), "expected tb1p address, got {}", addr_str);
    }
}
