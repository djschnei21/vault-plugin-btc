package wallet

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
)

func TestGenerateSeed(t *testing.T) {
	t.Run("generates correct length seed", func(t *testing.T) {
		seed, err := GenerateSeed()
		if err != nil {
			t.Fatalf("GenerateSeed() error = %v", err)
		}
		if len(seed) != SeedLength {
			t.Errorf("GenerateSeed() length = %d, want %d", len(seed), SeedLength)
		}
	})

	t.Run("generates unique seeds", func(t *testing.T) {
		seed1, err := GenerateSeed()
		if err != nil {
			t.Fatalf("GenerateSeed() error = %v", err)
		}
		seed2, err := GenerateSeed()
		if err != nil {
			t.Fatalf("GenerateSeed() error = %v", err)
		}
		if bytes.Equal(seed1, seed2) {
			t.Error("GenerateSeed() generated identical seeds")
		}
	})
}

func TestNetworkParams(t *testing.T) {
	tests := []struct {
		name    string
		network string
		wantErr bool
	}{
		{"mainnet", "mainnet", false},
		{"testnet4", "testnet4", false},
		{"invalid", "invalid", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := NetworkParams(tt.network)
			if (err != nil) != tt.wantErr {
				t.Errorf("NetworkParams(%q) error = %v, wantErr %v", tt.network, err, tt.wantErr)
				return
			}
			if !tt.wantErr && params == nil {
				t.Errorf("NetworkParams(%q) returned nil params", tt.network)
			}
		})
	}
}

func TestDeriveAccountKey(t *testing.T) {
	// Use a known seed for deterministic testing
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	tests := []struct {
		name    string
		network string
		account uint32
		wantErr bool
	}{
		{"mainnet account 0", "mainnet", 0, false},
		{"mainnet account 1", "mainnet", 1, false},
		{"testnet4 account 0", "testnet4", 0, false},
		{"invalid network", "invalid", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := DeriveAccountKey(seed, tt.network, tt.account)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeriveAccountKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if key == nil {
					t.Error("DeriveAccountKey() returned nil key")
				}
				if !key.IsPrivate() {
					t.Error("DeriveAccountKey() returned non-private key")
				}
			}
		})
	}
}

func TestDeriveAddressKey(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	accountKey, err := DeriveAccountKey(seed, "mainnet", 0)
	if err != nil {
		t.Fatalf("DeriveAccountKey() error = %v", err)
	}

	tests := []struct {
		name   string
		change uint32
		index  uint32
	}{
		{"external chain index 0", 0, 0},
		{"external chain index 1", 0, 1},
		{"external chain index 100", 0, 100},
		{"internal chain index 0", 1, 0},
		{"internal chain index 1", 1, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := DeriveAddressKey(accountKey, tt.change, tt.index)
			if err != nil {
				t.Errorf("DeriveAddressKey() error = %v", err)
				return
			}
			if key == nil {
				t.Error("DeriveAddressKey() returned nil key")
			}
			if !key.IsPrivate() {
				t.Error("DeriveAddressKey() returned non-private key")
			}
		})
	}
}

func TestDeriveReceivingKey(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	t.Run("derives different keys for different indices", func(t *testing.T) {
		key0, err := DeriveReceivingKey(seed, "mainnet", 0)
		if err != nil {
			t.Fatalf("DeriveReceivingKey(0) error = %v", err)
		}
		key1, err := DeriveReceivingKey(seed, "mainnet", 1)
		if err != nil {
			t.Fatalf("DeriveReceivingKey(1) error = %v", err)
		}

		if key0.String() == key1.String() {
			t.Error("DeriveReceivingKey() returned same key for different indices")
		}
	})

	t.Run("derives consistent keys for same index", func(t *testing.T) {
		key1, err := DeriveReceivingKey(seed, "mainnet", 5)
		if err != nil {
			t.Fatalf("DeriveReceivingKey() error = %v", err)
		}
		key2, err := DeriveReceivingKey(seed, "mainnet", 5)
		if err != nil {
			t.Fatalf("DeriveReceivingKey() error = %v", err)
		}

		if key1.String() != key2.String() {
			t.Error("DeriveReceivingKey() returned different keys for same index")
		}
	})
}

func TestDeriveChangeKey(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	t.Run("change key differs from receiving key", func(t *testing.T) {
		receivingKey, err := DeriveReceivingKey(seed, "mainnet", 0)
		if err != nil {
			t.Fatalf("DeriveReceivingKey() error = %v", err)
		}
		changeKey, err := DeriveChangeKey(seed, "mainnet", 0)
		if err != nil {
			t.Fatalf("DeriveChangeKey() error = %v", err)
		}

		if receivingKey.String() == changeKey.String() {
			t.Error("DeriveChangeKey() returned same key as DeriveReceivingKey()")
		}
	})
}

func TestGetPrivateKey(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	t.Run("extracts private key from extended key", func(t *testing.T) {
		extKey, err := DeriveReceivingKey(seed, "mainnet", 0)
		if err != nil {
			t.Fatalf("DeriveReceivingKey() error = %v", err)
		}

		privKey, err := GetPrivateKey(extKey)
		if err != nil {
			t.Errorf("GetPrivateKey() error = %v", err)
			return
		}
		if privKey == nil {
			t.Error("GetPrivateKey() returned nil")
		}
	})

	t.Run("fails for public key", func(t *testing.T) {
		extKey, err := DeriveReceivingKey(seed, "mainnet", 0)
		if err != nil {
			t.Fatalf("DeriveReceivingKey() error = %v", err)
		}

		pubKey, err := extKey.Neuter()
		if err != nil {
			t.Fatalf("Neuter() error = %v", err)
		}

		_, err = GetPrivateKey(pubKey)
		if err == nil {
			t.Error("GetPrivateKey() should fail for public key")
		}
	})
}

func TestGetPublicKey(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	t.Run("extracts public key from private extended key", func(t *testing.T) {
		extKey, err := DeriveReceivingKey(seed, "mainnet", 0)
		if err != nil {
			t.Fatalf("DeriveReceivingKey() error = %v", err)
		}

		pubKey, err := GetPublicKey(extKey)
		if err != nil {
			t.Errorf("GetPublicKey() error = %v", err)
			return
		}
		if pubKey == nil {
			t.Error("GetPublicKey() returned nil")
		}
	})

	t.Run("extracts public key from neutered extended key", func(t *testing.T) {
		extKey, err := DeriveReceivingKey(seed, "mainnet", 0)
		if err != nil {
			t.Fatalf("DeriveReceivingKey() error = %v", err)
		}

		neutered, err := extKey.Neuter()
		if err != nil {
			t.Fatalf("Neuter() error = %v", err)
		}

		pubKey, err := GetPublicKey(neutered)
		if err != nil {
			t.Errorf("GetPublicKey() error = %v", err)
			return
		}
		if pubKey == nil {
			t.Error("GetPublicKey() returned nil")
		}
	})
}

func TestDerivationPath(t *testing.T) {
	tests := []struct {
		name     string
		network  string
		change   uint32
		index    uint32
		expected string
	}{
		{"mainnet receiving 0", "mainnet", 0, 0, "m/84'/0'/0'/0/0"},
		{"mainnet receiving 5", "mainnet", 0, 5, "m/84'/0'/0'/0/5"},
		{"mainnet change 0", "mainnet", 1, 0, "m/84'/0'/0'/1/0"},
		{"testnet4 receiving 0", "testnet4", 0, 0, "m/84'/1'/0'/0/0"},
		{"testnet4 receiving 10", "testnet4", 0, 10, "m/84'/1'/0'/0/10"},
		{"testnet4 change 3", "testnet4", 1, 3, "m/84'/1'/0'/1/3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := DerivationPath(tt.network, tt.change, tt.index)
			if path != tt.expected {
				t.Errorf("DerivationPath() = %q, want %q", path, tt.expected)
			}
		})
	}
}

func TestBIP84Compliance(t *testing.T) {
	// Test vector from BIP84
	// Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
	// Seed: 5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4
	seedHex := "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
	seed, _ := hex.DecodeString(seedHex)

	// Expected first receiving address for BIP84 mainnet
	// Account 0, external chain, index 0
	// m/84'/0'/0'/0/0 should give bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
	expectedAddress := "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"

	address, err := GenerateAddressFromSeed(seed, "mainnet", 0)
	if err != nil {
		t.Fatalf("GenerateAddressFromSeed() error = %v", err)
	}

	if address != expectedAddress {
		t.Errorf("BIP84 compliance test failed:\ngot:  %s\nwant: %s", address, expectedAddress)
	}
}

func TestDeriveAccountKeyForType(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	t.Run("P2WPKH account key derivation", func(t *testing.T) {
		key, err := DeriveAccountKeyForType(seed, "mainnet", 0, AddressTypeP2WPKH)
		if err != nil {
			t.Fatalf("DeriveAccountKeyForType() error = %v", err)
		}
		if key == nil {
			t.Error("DeriveAccountKeyForType() returned nil key")
		}
		if !key.IsPrivate() {
			t.Error("DeriveAccountKeyForType() returned non-private key")
		}
	})

	t.Run("P2TR account key derivation", func(t *testing.T) {
		key, err := DeriveAccountKeyForType(seed, "mainnet", 0, AddressTypeP2TR)
		if err != nil {
			t.Fatalf("DeriveAccountKeyForType() error = %v", err)
		}
		if key == nil {
			t.Error("DeriveAccountKeyForType() returned nil key")
		}
	})

	t.Run("different address types produce different keys", func(t *testing.T) {
		p2wpkhKey, _ := DeriveAccountKeyForType(seed, "mainnet", 0, AddressTypeP2WPKH)
		p2trKey, _ := DeriveAccountKeyForType(seed, "mainnet", 0, AddressTypeP2TR)

		if p2wpkhKey.String() == p2trKey.String() {
			t.Error("P2WPKH and P2TR account keys should differ (different purpose)")
		}
	})

	t.Run("invalid address type fails", func(t *testing.T) {
		_, err := DeriveAccountKeyForType(seed, "mainnet", 0, "invalid")
		if err == nil {
			t.Error("DeriveAccountKeyForType() should fail for invalid address type")
		}
	})

	t.Run("testnet4 derivation", func(t *testing.T) {
		key, err := DeriveAccountKeyForType(seed, "testnet4", 0, AddressTypeP2WPKH)
		if err != nil {
			t.Fatalf("DeriveAccountKeyForType() error = %v", err)
		}
		if key == nil {
			t.Error("DeriveAccountKeyForType() returned nil key")
		}
	})

	t.Run("signet derivation", func(t *testing.T) {
		key, err := DeriveAccountKeyForType(seed, "signet", 0, AddressTypeP2WPKH)
		if err != nil {
			t.Fatalf("DeriveAccountKeyForType() error = %v", err)
		}
		if key == nil {
			t.Error("DeriveAccountKeyForType() returned nil key")
		}
	})
}

func TestDeriveReceivingKeyForType(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	t.Run("P2WPKH receiving key derivation", func(t *testing.T) {
		key, err := DeriveReceivingKeyForType(seed, "mainnet", 0, AddressTypeP2WPKH)
		if err != nil {
			t.Fatalf("DeriveReceivingKeyForType() error = %v", err)
		}
		if key == nil {
			t.Error("DeriveReceivingKeyForType() returned nil key")
		}
		if !key.IsPrivate() {
			t.Error("DeriveReceivingKeyForType() returned non-private key")
		}
	})

	t.Run("P2TR receiving key derivation", func(t *testing.T) {
		key, err := DeriveReceivingKeyForType(seed, "mainnet", 0, AddressTypeP2TR)
		if err != nil {
			t.Fatalf("DeriveReceivingKeyForType() error = %v", err)
		}
		if key == nil {
			t.Error("DeriveReceivingKeyForType() returned nil key")
		}
	})

	t.Run("different indices produce different keys", func(t *testing.T) {
		key0, _ := DeriveReceivingKeyForType(seed, "mainnet", 0, AddressTypeP2WPKH)
		key1, _ := DeriveReceivingKeyForType(seed, "mainnet", 1, AddressTypeP2WPKH)

		if key0.String() == key1.String() {
			t.Error("Different indices should produce different keys")
		}
	})

	t.Run("same index produces consistent key", func(t *testing.T) {
		key1, _ := DeriveReceivingKeyForType(seed, "mainnet", 5, AddressTypeP2TR)
		key2, _ := DeriveReceivingKeyForType(seed, "mainnet", 5, AddressTypeP2TR)

		if key1.String() != key2.String() {
			t.Error("Same index should produce same key")
		}
	})

	t.Run("receiving key matches legacy function for P2WPKH", func(t *testing.T) {
		legacyKey, _ := DeriveReceivingKey(seed, "mainnet", 0)
		newKey, _ := DeriveReceivingKeyForType(seed, "mainnet", 0, AddressTypeP2WPKH)

		if legacyKey.String() != newKey.String() {
			t.Error("DeriveReceivingKeyForType(P2WPKH) should match DeriveReceivingKey")
		}
	})
}

func TestDeriveChangeKeyForType(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	t.Run("P2WPKH change key derivation", func(t *testing.T) {
		key, err := DeriveChangeKeyForType(seed, "mainnet", 0, AddressTypeP2WPKH)
		if err != nil {
			t.Fatalf("DeriveChangeKeyForType() error = %v", err)
		}
		if key == nil {
			t.Error("DeriveChangeKeyForType() returned nil key")
		}
		if !key.IsPrivate() {
			t.Error("DeriveChangeKeyForType() returned non-private key")
		}
	})

	t.Run("P2TR change key derivation", func(t *testing.T) {
		key, err := DeriveChangeKeyForType(seed, "mainnet", 0, AddressTypeP2TR)
		if err != nil {
			t.Fatalf("DeriveChangeKeyForType() error = %v", err)
		}
		if key == nil {
			t.Error("DeriveChangeKeyForType() returned nil key")
		}
	})

	t.Run("change key differs from receiving key", func(t *testing.T) {
		receivingKey, _ := DeriveReceivingKeyForType(seed, "mainnet", 0, AddressTypeP2WPKH)
		changeKey, _ := DeriveChangeKeyForType(seed, "mainnet", 0, AddressTypeP2WPKH)

		if receivingKey.String() == changeKey.String() {
			t.Error("Change key should differ from receiving key at same index")
		}
	})

	t.Run("change key matches legacy function for P2WPKH", func(t *testing.T) {
		legacyKey, _ := DeriveChangeKey(seed, "mainnet", 0)
		newKey, _ := DeriveChangeKeyForType(seed, "mainnet", 0, AddressTypeP2WPKH)

		if legacyKey.String() != newKey.String() {
			t.Error("DeriveChangeKeyForType(P2WPKH) should match DeriveChangeKey")
		}
	})
}

func TestDerivationPathForType(t *testing.T) {
	tests := []struct {
		name        string
		network     string
		change      uint32
		index       uint32
		addressType string
		expected    string
	}{
		{"P2WPKH mainnet receiving 0", "mainnet", 0, 0, AddressTypeP2WPKH, "m/84'/0'/0'/0/0"},
		{"P2WPKH mainnet receiving 5", "mainnet", 0, 5, AddressTypeP2WPKH, "m/84'/0'/0'/0/5"},
		{"P2WPKH mainnet change 0", "mainnet", 1, 0, AddressTypeP2WPKH, "m/84'/0'/0'/1/0"},
		{"P2WPKH testnet4 receiving 0", "testnet4", 0, 0, AddressTypeP2WPKH, "m/84'/1'/0'/0/0"},
		{"P2TR mainnet receiving 0", "mainnet", 0, 0, AddressTypeP2TR, "m/86'/0'/0'/0/0"},
		{"P2TR mainnet receiving 10", "mainnet", 0, 10, AddressTypeP2TR, "m/86'/0'/0'/0/10"},
		{"P2TR mainnet change 0", "mainnet", 1, 0, AddressTypeP2TR, "m/86'/0'/0'/1/0"},
		{"P2TR mainnet change 3", "mainnet", 1, 3, AddressTypeP2TR, "m/86'/0'/0'/1/3"},
		{"P2TR testnet4 receiving 0", "testnet4", 0, 0, AddressTypeP2TR, "m/86'/1'/0'/0/0"},
		{"P2TR testnet4 change 5", "testnet4", 1, 5, AddressTypeP2TR, "m/86'/1'/0'/1/5"},
		{"P2TR signet receiving 0", "signet", 0, 0, AddressTypeP2TR, "m/86'/1'/0'/0/0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := DerivationPathForType(tt.network, tt.change, tt.index, tt.addressType)
			if path != tt.expected {
				t.Errorf("DerivationPathForType() = %q, want %q", path, tt.expected)
			}
		})
	}
}

func TestDerivationPathBackwardsCompatibility(t *testing.T) {
	// Ensure DerivationPath returns same result as DerivationPathForType with P2WPKH
	tests := []struct {
		network string
		change  uint32
		index   uint32
	}{
		{"mainnet", 0, 0},
		{"mainnet", 0, 5},
		{"mainnet", 1, 0},
		{"testnet4", 0, 0},
		{"testnet4", 1, 10},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			legacy := DerivationPath(tt.network, tt.change, tt.index)
			newPath := DerivationPathForType(tt.network, tt.change, tt.index, AddressTypeP2WPKH)

			if legacy != newPath {
				t.Errorf("DerivationPath() = %q, DerivationPathForType() = %q", legacy, newPath)
			}
		})
	}
}

func TestNetworkParamsSignet(t *testing.T) {
	params, err := NetworkParams("signet")
	if err != nil {
		t.Fatalf("NetworkParams(signet) error = %v", err)
	}
	if params == nil {
		t.Error("NetworkParams(signet) returned nil params")
	}
}

func TestHardenedKeyDerivation(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	params, _ := NetworkParams("mainnet")

	// Verify that purpose, coin_type, and account levels use hardened derivation
	// by checking that we can't derive them from a neutered (public) key
	masterKey, err := hdkeychain.NewMaster(seed, params)
	if err != nil {
		t.Fatalf("NewMaster() error = %v", err)
	}

	// Neuter the master key
	neuteredMaster, err := masterKey.Neuter()
	if err != nil {
		t.Fatalf("Neuter() error = %v", err)
	}

	// Attempting to derive hardened child from public key should fail
	_, err = neuteredMaster.Derive(hdkeychain.HardenedKeyStart + 84)
	if err == nil {
		t.Error("Should not be able to derive hardened child from public key")
	}
}

func TestGetAccountXpub(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	t.Run("mainnet p2wpkh returns zpub", func(t *testing.T) {
		xpub, path, err := GetAccountXpub(seed, "mainnet", AddressTypeP2WPKH)
		if err != nil {
			t.Fatalf("GetAccountXpub() error = %v", err)
		}

		// zpub starts with "zpub"
		if len(xpub) < 4 || xpub[:4] != "zpub" {
			t.Errorf("GetAccountXpub() mainnet p2wpkh should return zpub, got %s", xpub[:10])
		}

		// Path should be BIP84
		if path != "m/84'/0'/0'" {
			t.Errorf("GetAccountXpub() path = %s, want m/84'/0'/0'", path)
		}
	})

	t.Run("testnet p2wpkh returns vpub", func(t *testing.T) {
		xpub, path, err := GetAccountXpub(seed, "testnet4", AddressTypeP2WPKH)
		if err != nil {
			t.Fatalf("GetAccountXpub() error = %v", err)
		}

		// vpub starts with "vpub"
		if len(xpub) < 4 || xpub[:4] != "vpub" {
			t.Errorf("GetAccountXpub() testnet p2wpkh should return vpub, got %s", xpub[:10])
		}

		// Path should be BIP84 testnet
		if path != "m/84'/1'/0'" {
			t.Errorf("GetAccountXpub() path = %s, want m/84'/1'/0'", path)
		}
	})

	t.Run("mainnet p2tr returns xpub", func(t *testing.T) {
		xpub, path, err := GetAccountXpub(seed, "mainnet", AddressTypeP2TR)
		if err != nil {
			t.Fatalf("GetAccountXpub() error = %v", err)
		}

		// p2tr uses standard xpub format (no SLIP-0132 standard)
		if len(xpub) < 4 || xpub[:4] != "xpub" {
			t.Errorf("GetAccountXpub() mainnet p2tr should return xpub, got %s", xpub[:10])
		}

		// Path should be BIP86
		if path != "m/86'/0'/0'" {
			t.Errorf("GetAccountXpub() path = %s, want m/86'/0'/0'", path)
		}
	})

	t.Run("testnet p2tr returns tpub", func(t *testing.T) {
		xpub, path, err := GetAccountXpub(seed, "testnet4", AddressTypeP2TR)
		if err != nil {
			t.Fatalf("GetAccountXpub() error = %v", err)
		}

		// p2tr uses standard tpub format on testnet
		if len(xpub) < 4 || xpub[:4] != "tpub" {
			t.Errorf("GetAccountXpub() testnet p2tr should return tpub, got %s", xpub[:10])
		}

		// Path should be BIP86 testnet
		if path != "m/86'/1'/0'" {
			t.Errorf("GetAccountXpub() path = %s, want m/86'/1'/0'", path)
		}
	})

	t.Run("same seed produces same xpub", func(t *testing.T) {
		xpub1, _, _ := GetAccountXpub(seed, "mainnet", AddressTypeP2WPKH)
		xpub2, _, _ := GetAccountXpub(seed, "mainnet", AddressTypeP2WPKH)

		if xpub1 != xpub2 {
			t.Errorf("GetAccountXpub() should be deterministic, got different results")
		}
	})

	t.Run("different address types produce different xpubs", func(t *testing.T) {
		xpubP2WPKH, _, _ := GetAccountXpub(seed, "mainnet", AddressTypeP2WPKH)
		xpubP2TR, _, _ := GetAccountXpub(seed, "mainnet", AddressTypeP2TR)

		if xpubP2WPKH == xpubP2TR {
			t.Error("GetAccountXpub() should produce different keys for different address types")
		}
	})

	t.Run("invalid network returns error", func(t *testing.T) {
		_, _, err := GetAccountXpub(seed, "invalid", AddressTypeP2WPKH)
		if err == nil {
			t.Error("GetAccountXpub() should fail for invalid network")
		}
	})

	t.Run("invalid address type returns error", func(t *testing.T) {
		_, _, err := GetAccountXpub(seed, "mainnet", "invalid")
		if err == nil {
			t.Error("GetAccountXpub() should fail for invalid address type")
		}
	})
}
