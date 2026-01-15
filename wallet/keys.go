package wallet

import (
	"crypto/rand"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

const (
	// SeedLength is the recommended seed length (256 bits)
	SeedLength = 32

	// BIP84Purpose is the purpose for native SegWit (P2WPKH)
	BIP84Purpose = 84

	// BIP86Purpose is the purpose for Taproot (P2TR)
	BIP86Purpose = 86

	// CoinTypeBitcoin is the coin type for Bitcoin mainnet
	CoinTypeBitcoin = 0

	// CoinTypeBitcoinTestnet is the coin type for Bitcoin testnet
	CoinTypeBitcoinTestnet = 1

	// Address type constants
	AddressTypeP2WPKH = "p2wpkh"
	AddressTypeP2TR   = "p2tr"
)

// NetworkParams returns the chain configuration for the given network name
func NetworkParams(network string) (*chaincfg.Params, error) {
	switch network {
	case "mainnet":
		return &chaincfg.MainNetParams, nil
	case "testnet4":
		// Testnet4 uses same address format as testnet3 (tb1... addresses)
		return &chaincfg.TestNet3Params, nil
	case "signet":
		return &chaincfg.SigNetParams, nil
	default:
		return nil, fmt.Errorf("unknown network: %s (supported: mainnet, testnet4, signet)", network)
	}
}

// GenerateSeed creates a cryptographically secure random seed
func GenerateSeed() ([]byte, error) {
	seed := make([]byte, SeedLength)
	n, err := rand.Read(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to generate seed: %w", err)
	}
	// Verify we got exactly the bytes we asked for (paranoid check)
	if n != SeedLength {
		return nil, fmt.Errorf("insufficient random bytes: got %d, need %d", n, SeedLength)
	}
	return seed, nil
}

// DeriveAccountKey derives the account extended key from a seed using BIP84
// Path: m/84'/coin_type'/account'
func DeriveAccountKey(seed []byte, network string, account uint32) (*hdkeychain.ExtendedKey, error) {
	return DeriveAccountKeyForType(seed, network, account, AddressTypeP2WPKH)
}

// DeriveAccountKeyForType derives the account extended key for a specific address type
// BIP84 Path: m/84'/coin_type'/account' (P2WPKH)
// BIP86 Path: m/86'/coin_type'/account' (P2TR)
func DeriveAccountKeyForType(seed []byte, network string, account uint32, addressType string) (*hdkeychain.ExtendedKey, error) {
	params, err := NetworkParams(network)
	if err != nil {
		return nil, err
	}

	// Create master key from seed
	masterKey, err := hdkeychain.NewMaster(seed, params)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// Determine purpose based on address type
	var purpose uint32
	switch addressType {
	case AddressTypeP2TR:
		purpose = BIP86Purpose
	case AddressTypeP2WPKH:
		purpose = BIP84Purpose
	default:
		return nil, fmt.Errorf("unknown address type: %s", addressType)
	}

	// Derive purpose: m/84' or m/86'
	purposeKey, err := masterKey.Derive(hdkeychain.HardenedKeyStart + purpose)
	if err != nil {
		return nil, fmt.Errorf("failed to derive purpose key: %w", err)
	}

	// Derive coin type: m/purpose'/0' for mainnet, m/purpose'/1' for testnet4/signet
	coinType := CoinTypeBitcoin
	if network == "testnet4" || network == "signet" {
		coinType = CoinTypeBitcoinTestnet
	}
	coinTypeKey, err := purposeKey.Derive(hdkeychain.HardenedKeyStart + uint32(coinType))
	if err != nil {
		return nil, fmt.Errorf("failed to derive coin type key: %w", err)
	}

	// Derive account: m/purpose'/coin_type'/account'
	accountKey, err := coinTypeKey.Derive(hdkeychain.HardenedKeyStart + account)
	if err != nil {
		return nil, fmt.Errorf("failed to derive account key: %w", err)
	}

	return accountKey, nil
}

// DeriveAddressKey derives a key for a specific address index
// Path: m/84'/coin_type'/account'/change/index
// change: 0 for external (receiving), 1 for internal (change)
func DeriveAddressKey(accountKey *hdkeychain.ExtendedKey, change, index uint32) (*hdkeychain.ExtendedKey, error) {
	// Derive change level (external=0, internal=1)
	changeKey, err := accountKey.Derive(change)
	if err != nil {
		return nil, fmt.Errorf("failed to derive change key: %w", err)
	}

	// Derive address index
	addressKey, err := changeKey.Derive(index)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address key: %w", err)
	}

	return addressKey, nil
}

// DeriveReceivingKey derives a key for receiving (external chain) using BIP84
// Path: m/84'/coin_type'/0'/0/index
func DeriveReceivingKey(seed []byte, network string, index uint32) (*hdkeychain.ExtendedKey, error) {
	return DeriveReceivingKeyForType(seed, network, index, AddressTypeP2WPKH)
}

// DeriveReceivingKeyForType derives a key for receiving with a specific address type
// BIP84 Path: m/84'/coin_type'/0'/0/index (P2WPKH)
// BIP86 Path: m/86'/coin_type'/0'/0/index (P2TR)
func DeriveReceivingKeyForType(seed []byte, network string, index uint32, addressType string) (*hdkeychain.ExtendedKey, error) {
	accountKey, err := DeriveAccountKeyForType(seed, network, 0, addressType)
	if err != nil {
		return nil, err
	}

	return DeriveAddressKey(accountKey, 0, index)
}

// DeriveChangeKey derives a key for change (internal chain) using BIP84
// Path: m/84'/coin_type'/0'/1/index
func DeriveChangeKey(seed []byte, network string, index uint32) (*hdkeychain.ExtendedKey, error) {
	return DeriveChangeKeyForType(seed, network, index, AddressTypeP2WPKH)
}

// DeriveChangeKeyForType derives a key for change with a specific address type
// BIP84 Path: m/84'/coin_type'/0'/1/index (P2WPKH)
// BIP86 Path: m/86'/coin_type'/0'/1/index (P2TR)
func DeriveChangeKeyForType(seed []byte, network string, index uint32, addressType string) (*hdkeychain.ExtendedKey, error) {
	accountKey, err := DeriveAccountKeyForType(seed, network, 0, addressType)
	if err != nil {
		return nil, err
	}

	return DeriveAddressKey(accountKey, 1, index)
}

// GetPrivateKey extracts the EC private key from an extended key
func GetPrivateKey(key *hdkeychain.ExtendedKey) (*btcec.PrivateKey, error) {
	if !key.IsPrivate() {
		return nil, fmt.Errorf("extended key is not private")
	}

	privKey, err := key.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get EC private key: %w", err)
	}

	return privKey, nil
}

// GetPublicKey extracts the EC public key from an extended key
func GetPublicKey(key *hdkeychain.ExtendedKey) (*btcec.PublicKey, error) {
	pubKey, err := key.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get EC public key: %w", err)
	}

	return pubKey, nil
}

// DerivationPath returns the BIP84 derivation path string for an address
func DerivationPath(network string, change, index uint32) string {
	return DerivationPathForType(network, change, index, AddressTypeP2WPKH)
}

// DerivationPathForType returns the derivation path string for an address with a specific type
func DerivationPathForType(network string, change, index uint32, addressType string) string {
	coinType := CoinTypeBitcoin
	if network == "testnet4" || network == "signet" {
		coinType = CoinTypeBitcoinTestnet
	}
	purpose := BIP84Purpose
	if addressType == AddressTypeP2TR {
		purpose = BIP86Purpose
	}
	return fmt.Sprintf("m/%d'/%d'/0'/%d/%d", purpose, coinType, change, index)
}
