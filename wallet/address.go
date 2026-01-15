package wallet

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/txscript"
)

// GenerateP2WPKHAddress generates a native SegWit (bech32) address from an extended key
func GenerateP2WPKHAddress(key *hdkeychain.ExtendedKey, network string) (string, error) {
	params, err := NetworkParams(network)
	if err != nil {
		return "", err
	}

	pubKey, err := key.ECPubKey()
	if err != nil {
		return "", fmt.Errorf("failed to get public key: %w", err)
	}

	// Create P2WPKH address (native SegWit, bc1...)
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	addr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, params)
	if err != nil {
		return "", fmt.Errorf("failed to create P2WPKH address: %w", err)
	}

	return addr.EncodeAddress(), nil
}

// GenerateP2TRAddress generates a Taproot (bech32m) address from an extended key
// Uses BIP86 key-path only spending (no script tree)
func GenerateP2TRAddress(key *hdkeychain.ExtendedKey, network string) (string, error) {
	params, err := NetworkParams(network)
	if err != nil {
		return "", err
	}

	pubKey, err := key.ECPubKey()
	if err != nil {
		return "", fmt.Errorf("failed to get public key: %w", err)
	}

	// Compute the taproot output key (internal key tweaked with no script tree)
	// This follows BIP86 for key-path only spending
	taprootKey := txscript.ComputeTaprootKeyNoScript(pubKey)

	// Create P2TR address (bc1p... for mainnet, tb1p... for testnet)
	addr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(taprootKey), params)
	if err != nil {
		return "", fmt.Errorf("failed to create P2TR address: %w", err)
	}

	return addr.EncodeAddress(), nil
}

// GenerateAddressFromSeed generates an address for a specific index from a seed
// Uses the default P2WPKH address type (for backwards compatibility)
func GenerateAddressFromSeed(seed []byte, network string, index uint32) (string, error) {
	return GenerateAddressFromSeedForType(seed, network, index, AddressTypeP2WPKH)
}

// GenerateAddressFromSeedForType generates an address for a specific index and address type
func GenerateAddressFromSeedForType(seed []byte, network string, index uint32, addressType string) (string, error) {
	key, err := DeriveReceivingKeyForType(seed, network, index, addressType)
	if err != nil {
		return "", err
	}

	switch addressType {
	case AddressTypeP2TR:
		return GenerateP2TRAddress(key, network)
	case AddressTypeP2WPKH:
		return GenerateP2WPKHAddress(key, network)
	default:
		return "", fmt.Errorf("unsupported address type: %s", addressType)
	}
}

// GenerateChangeAddressFromSeedForType generates a change address (internal chain) for a specific index
// Change addresses use derivation path m/purpose'/coin'/0'/1/index (note chain=1)
func GenerateChangeAddressFromSeedForType(seed []byte, network string, index uint32, addressType string) (string, error) {
	key, err := DeriveChangeKeyForType(seed, network, index, addressType)
	if err != nil {
		return "", err
	}

	switch addressType {
	case AddressTypeP2TR:
		return GenerateP2TRAddress(key, network)
	case AddressTypeP2WPKH:
		return GenerateP2WPKHAddress(key, network)
	default:
		return "", fmt.Errorf("unsupported address type: %s", addressType)
	}
}

// GetScriptPubKey returns the scriptPubKey for a P2WPKH address
func GetScriptPubKey(address string, network string) ([]byte, error) {
	params, err := NetworkParams(network)
	if err != nil {
		return nil, err
	}

	addr, err := btcutil.DecodeAddress(address, params)
	if err != nil {
		return nil, fmt.Errorf("failed to decode address: %w", err)
	}

	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to create scriptPubKey: %w", err)
	}

	return script, nil
}

// AddressToScriptHash converts a Bitcoin address to an Electrum scripthash
// The scripthash is SHA256 of the scriptPubKey, reversed (little-endian)
func AddressToScriptHash(address string, network string) (string, error) {
	scriptPubKey, err := GetScriptPubKey(address, network)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(scriptPubKey)

	// Reverse for little-endian (Electrum format)
	for i, j := 0, len(hash)-1; i < j; i, j = i+1, j-1 {
		hash[i], hash[j] = hash[j], hash[i]
	}

	return hex.EncodeToString(hash[:]), nil
}

// ValidateAddress checks if an address is valid for the given network
func ValidateAddress(address string, network string) error {
	params, err := NetworkParams(network)
	if err != nil {
		return err
	}

	addr, err := btcutil.DecodeAddress(address, params)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}

	if !addr.IsForNet(params) {
		return fmt.Errorf("address is not for %s network", network)
	}

	return nil
}

// GetAddressType returns the type of a Bitcoin address
func GetAddressType(address string, network string) (string, error) {
	params, err := NetworkParams(network)
	if err != nil {
		return "", err
	}

	addr, err := btcutil.DecodeAddress(address, params)
	if err != nil {
		return "", fmt.Errorf("invalid address: %w", err)
	}

	switch addr.(type) {
	case *btcutil.AddressPubKeyHash:
		return "p2pkh", nil
	case *btcutil.AddressScriptHash:
		return "p2sh", nil
	case *btcutil.AddressWitnessPubKeyHash:
		return "p2wpkh", nil
	case *btcutil.AddressWitnessScriptHash:
		return "p2wsh", nil
	case *btcutil.AddressTaproot:
		return "p2tr", nil
	default:
		return "unknown", nil
	}
}

// AddressInfo contains information about a generated address
type AddressInfo struct {
	Address        string `json:"address"`
	Index          uint32 `json:"index"`
	DerivationPath string `json:"derivation_path"`
	ScriptHash     string `json:"scripthash"`
}

// GenerateAddressInfo generates complete address information
// Uses P2WPKH for backwards compatibility
func GenerateAddressInfo(seed []byte, network string, index uint32) (*AddressInfo, error) {
	return GenerateAddressInfoForType(seed, network, index, AddressTypeP2WPKH)
}

// GenerateAddressInfoForType generates complete address information for a specific address type
func GenerateAddressInfoForType(seed []byte, network string, index uint32, addressType string) (*AddressInfo, error) {
	address, err := GenerateAddressFromSeedForType(seed, network, index, addressType)
	if err != nil {
		return nil, err
	}

	scripthash, err := AddressToScriptHash(address, network)
	if err != nil {
		return nil, err
	}

	return &AddressInfo{
		Address:        address,
		Index:          index,
		DerivationPath: DerivationPathForType(network, 0, index, addressType),
		ScriptHash:     scripthash,
	}, nil
}
