package wallet

import (
	"crypto/rand"
	"crypto/sha256"
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

// SLIP-0132 version bytes for extended public keys
// These allow wallets like Sparrow to recognize the key type from the prefix
var (
	// BIP84 zpub (mainnet native segwit) - version 0x04b24746
	zpubVersion = [4]byte{0x04, 0xb2, 0x47, 0x46}
	// BIP84 vpub (testnet native segwit) - version 0x045f1cf6
	vpubVersion = [4]byte{0x04, 0x5f, 0x1c, 0xf6}
)

// GetAccountXpub returns the account-level extended public key for watch-only wallet import.
// For BIP84 (p2wpkh), returns zpub (mainnet) or vpub (testnet) format per SLIP-0132.
// For BIP86 (p2tr), returns standard xpub/tpub format (no SLIP-0132 standard exists).
// The returned key can be imported into wallets like Sparrow as a watch-only wallet.
func GetAccountXpub(seed []byte, network string, addressType string) (string, string, error) {
	// Derive the account key (private)
	accountKey, err := DeriveAccountKeyForType(seed, network, 0, addressType)
	if err != nil {
		return "", "", fmt.Errorf("failed to derive account key: %w", err)
	}

	// Get the public key version (neutered)
	accountPubKey, err := accountKey.Neuter()
	if err != nil {
		return "", "", fmt.Errorf("failed to neuter account key: %w", err)
	}

	// Get the derivation path for documentation
	coinType := CoinTypeBitcoin
	if network == "testnet4" || network == "signet" {
		coinType = CoinTypeBitcoinTestnet
	}
	purpose := BIP84Purpose
	if addressType == AddressTypeP2TR {
		purpose = BIP86Purpose
	}
	derivationPath := fmt.Sprintf("m/%d'/%d'/0'", purpose, coinType)

	// For BIP84, convert to SLIP-0132 format (zpub/vpub)
	if addressType == AddressTypeP2WPKH {
		xpubStr := accountPubKey.String()
		converted, err := convertToSlip132(xpubStr, network)
		if err != nil {
			return "", "", fmt.Errorf("failed to convert to SLIP-0132: %w", err)
		}
		return converted, derivationPath, nil
	}

	// For BIP86, return standard format (no SLIP-0132 standard for Taproot)
	return accountPubKey.String(), derivationPath, nil
}

// convertToSlip132 converts a standard xpub/tpub to SLIP-0132 zpub/vpub format
func convertToSlip132(xpub string, network string) (string, error) {
	// Decode the base58check encoded xpub
	decoded, version, err := decodeBase58Check(xpub)
	if err != nil {
		return "", err
	}

	// Verify it's a public key (xpub or tpub)
	params, err := NetworkParams(network)
	if err != nil {
		return "", err
	}

	xpubBytes := params.HDPublicKeyID[:]
	if !bytesEqual(version, xpubBytes) {
		return "", fmt.Errorf("unexpected version bytes: got %x, expected %x", version, xpubBytes)
	}

	// Replace version bytes with SLIP-0132 version
	var newVersion [4]byte
	if network == "mainnet" {
		newVersion = zpubVersion
	} else {
		newVersion = vpubVersion
	}

	return encodeBase58Check(decoded, newVersion[:]), nil
}

// decodeBase58Check decodes a base58check encoded string, returning the payload and version
func decodeBase58Check(encoded string) ([]byte, []byte, error) {
	// Base58 alphabet
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	// Decode base58
	var result []byte
	for _, c := range encoded {
		charIndex := -1
		for i, a := range alphabet {
			if a == c {
				charIndex = i
				break
			}
		}
		if charIndex == -1 {
			return nil, nil, fmt.Errorf("invalid base58 character: %c", c)
		}

		// Multiply result by 58 and add charIndex
		carry := charIndex
		for i := len(result) - 1; i >= 0; i-- {
			carry += int(result[i]) * 58
			result[i] = byte(carry & 0xff)
			carry >>= 8
		}
		for carry > 0 {
			result = append([]byte{byte(carry & 0xff)}, result...)
			carry >>= 8
		}
	}

	// Add leading zeros
	for _, c := range encoded {
		if c != '1' {
			break
		}
		result = append([]byte{0}, result...)
	}

	// Verify checksum (last 4 bytes)
	if len(result) < 5 {
		return nil, nil, fmt.Errorf("decoded data too short")
	}

	// Split into version (4 bytes) + payload + checksum (4 bytes)
	version := result[:4]
	payload := result[4 : len(result)-4]

	return payload, version, nil
}

// encodeBase58Check encodes data with version bytes using base58check
func encodeBase58Check(payload []byte, version []byte) string {
	// Base58 alphabet
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	// Combine version + payload
	data := append(version, payload...)

	// Calculate double SHA256 checksum
	hash1 := sha256Sum(data)
	hash2 := sha256Sum(hash1)
	checksum := hash2[:4]

	// Append checksum
	data = append(data, checksum...)

	// Count leading zeros
	var leadingZeros int
	for _, b := range data {
		if b != 0 {
			break
		}
		leadingZeros++
	}

	// Convert to base58
	var result []byte
	for _, b := range data {
		carry := int(b)
		for i := len(result) - 1; i >= 0; i-- {
			carry += int(result[i]) << 8
			result[i] = byte(carry % 58)
			carry /= 58
		}
		for carry > 0 {
			result = append([]byte{byte(carry % 58)}, result...)
			carry /= 58
		}
	}

	// Add leading '1's for each leading zero byte
	for i := 0; i < leadingZeros; i++ {
		result = append([]byte{0}, result...)
	}

	// Convert to alphabet
	encoded := make([]byte, len(result))
	for i, b := range result {
		encoded[i] = alphabet[b]
	}

	return string(encoded)
}

// sha256Sum computes SHA256 hash
func sha256Sum(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

// bytesEqual compares two byte slices
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
