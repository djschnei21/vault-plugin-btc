package wallet

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestGenerateP2WPKHAddress(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	tests := []struct {
		name    string
		network string
		index   uint32
		prefix  string
	}{
		{"mainnet index 0", "mainnet", 0, "bc1q"},
		{"mainnet index 1", "mainnet", 1, "bc1q"},
		{"testnet4 index 0", "testnet4", 0, "tb1q"},
		{"testnet4 index 1", "testnet4", 1, "tb1q"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := DeriveReceivingKey(seed, tt.network, tt.index)
			if err != nil {
				t.Fatalf("DeriveReceivingKey() error = %v", err)
			}

			address, err := GenerateP2WPKHAddress(key, tt.network)
			if err != nil {
				t.Errorf("GenerateP2WPKHAddress() error = %v", err)
				return
			}

			if !strings.HasPrefix(address, tt.prefix) {
				t.Errorf("GenerateP2WPKHAddress() = %q, want prefix %q", address, tt.prefix)
			}

			// Bech32 addresses should be lowercase
			if address != strings.ToLower(address) {
				t.Errorf("GenerateP2WPKHAddress() should return lowercase address, got %q", address)
			}
		})
	}
}

func TestGenerateP2TRAddress(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	tests := []struct {
		name    string
		network string
		index   uint32
		prefix  string
	}{
		{"mainnet index 0", "mainnet", 0, "bc1p"},
		{"mainnet index 1", "mainnet", 1, "bc1p"},
		{"testnet4 index 0", "testnet4", 0, "tb1p"},
		{"testnet4 index 1", "testnet4", 1, "tb1p"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := DeriveReceivingKeyForType(seed, tt.network, tt.index, AddressTypeP2TR)
			if err != nil {
				t.Fatalf("DeriveReceivingKeyForType() error = %v", err)
			}

			address, err := GenerateP2TRAddress(key, tt.network)
			if err != nil {
				t.Errorf("GenerateP2TRAddress() error = %v", err)
				return
			}

			if !strings.HasPrefix(address, tt.prefix) {
				t.Errorf("GenerateP2TRAddress() = %q, want prefix %q", address, tt.prefix)
			}

			// Bech32m addresses should be lowercase
			if address != strings.ToLower(address) {
				t.Errorf("GenerateP2TRAddress() should return lowercase address, got %q", address)
			}

			// P2TR address should be 62 characters (bc1p + 58 chars for mainnet)
			if tt.network == "mainnet" && len(address) != 62 {
				t.Errorf("GenerateP2TRAddress() length = %d, want 62 for mainnet", len(address))
			}
		})
	}
}

func TestGenerateAddressFromSeedForType(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	t.Run("P2WPKH address generation", func(t *testing.T) {
		addr, err := GenerateAddressFromSeedForType(seed, "mainnet", 0, AddressTypeP2WPKH)
		if err != nil {
			t.Fatalf("GenerateAddressFromSeedForType() error = %v", err)
		}
		if !strings.HasPrefix(addr, "bc1q") {
			t.Errorf("P2WPKH address should have bc1q prefix, got %q", addr)
		}
	})

	t.Run("P2TR address generation", func(t *testing.T) {
		addr, err := GenerateAddressFromSeedForType(seed, "mainnet", 0, AddressTypeP2TR)
		if err != nil {
			t.Fatalf("GenerateAddressFromSeedForType() error = %v", err)
		}
		if !strings.HasPrefix(addr, "bc1p") {
			t.Errorf("P2TR address should have bc1p prefix, got %q", addr)
		}
	})

	t.Run("different address types produce different addresses", func(t *testing.T) {
		p2wpkh, _ := GenerateAddressFromSeedForType(seed, "mainnet", 0, AddressTypeP2WPKH)
		p2tr, _ := GenerateAddressFromSeedForType(seed, "mainnet", 0, AddressTypeP2TR)
		if p2wpkh == p2tr {
			t.Error("P2WPKH and P2TR addresses should be different")
		}
	})

	t.Run("invalid address type fails", func(t *testing.T) {
		_, err := GenerateAddressFromSeedForType(seed, "mainnet", 0, "invalid")
		if err == nil {
			t.Error("GenerateAddressFromSeedForType() should fail for invalid address type")
		}
	})
}

func TestGenerateAddressFromSeed(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	t.Run("generates different addresses for different indices", func(t *testing.T) {
		addr0, err := GenerateAddressFromSeed(seed, "mainnet", 0)
		if err != nil {
			t.Fatalf("GenerateAddressFromSeed(0) error = %v", err)
		}
		addr1, err := GenerateAddressFromSeed(seed, "mainnet", 1)
		if err != nil {
			t.Fatalf("GenerateAddressFromSeed(1) error = %v", err)
		}

		if addr0 == addr1 {
			t.Error("GenerateAddressFromSeed() returned same address for different indices")
		}
	})

	t.Run("generates consistent addresses for same index", func(t *testing.T) {
		addr1, err := GenerateAddressFromSeed(seed, "mainnet", 5)
		if err != nil {
			t.Fatalf("GenerateAddressFromSeed() error = %v", err)
		}
		addr2, err := GenerateAddressFromSeed(seed, "mainnet", 5)
		if err != nil {
			t.Fatalf("GenerateAddressFromSeed() error = %v", err)
		}

		if addr1 != addr2 {
			t.Errorf("GenerateAddressFromSeed() returned different addresses: %q vs %q", addr1, addr2)
		}
	})

	t.Run("fails for invalid network", func(t *testing.T) {
		_, err := GenerateAddressFromSeed(seed, "invalid", 0)
		if err == nil {
			t.Error("GenerateAddressFromSeed() should fail for invalid network")
		}
	})
}

func TestGetScriptPubKey(t *testing.T) {
	tests := []struct {
		name        string
		address     string
		network     string
		wantErr     bool
		scriptLen   int
		scriptStart []byte
	}{
		{
			name:        "mainnet P2WPKH",
			address:     "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
			network:     "mainnet",
			wantErr:     false,
			scriptLen:   22,
			scriptStart: []byte{0x00, 0x14}, // OP_0 OP_PUSHBYTES_20
		},
		{
			name:        "testnet4 P2WPKH",
			address:     "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
			network:     "testnet4",
			wantErr:     false,
			scriptLen:   22,
			scriptStart: []byte{0x00, 0x14},
		},
		{
			name:    "invalid address",
			address: "invalid",
			network: "mainnet",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script, err := GetScriptPubKey(tt.address, tt.network)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetScriptPubKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(script) != tt.scriptLen {
					t.Errorf("GetScriptPubKey() script length = %d, want %d", len(script), tt.scriptLen)
				}
				if len(tt.scriptStart) > 0 && len(script) >= len(tt.scriptStart) {
					for i, b := range tt.scriptStart {
						if script[i] != b {
							t.Errorf("GetScriptPubKey() script[%d] = %x, want %x", i, script[i], b)
						}
					}
				}
			}
		})
	}
}

func TestAddressToScriptHash(t *testing.T) {
	tests := []struct {
		name           string
		address        string
		network        string
		wantErr        bool
		expectedLength int
	}{
		{
			name:           "mainnet P2WPKH",
			address:        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
			network:        "mainnet",
			wantErr:        false,
			expectedLength: 64, // 32 bytes = 64 hex chars
		},
		{
			name:           "testnet4 P2WPKH",
			address:        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
			network:        "testnet4",
			wantErr:        false,
			expectedLength: 64,
		},
		{
			name:    "invalid address",
			address: "invalid",
			network: "mainnet",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scripthash, err := AddressToScriptHash(tt.address, tt.network)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddressToScriptHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(scripthash) != tt.expectedLength {
					t.Errorf("AddressToScriptHash() length = %d, want %d", len(scripthash), tt.expectedLength)
				}
				// Verify it's valid hex
				_, err := hex.DecodeString(scripthash)
				if err != nil {
					t.Errorf("AddressToScriptHash() returned invalid hex: %v", err)
				}
			}
		})
	}

	t.Run("same address produces same scripthash", func(t *testing.T) {
		addr := "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
		sh1, _ := AddressToScriptHash(addr, "mainnet")
		sh2, _ := AddressToScriptHash(addr, "mainnet")
		if sh1 != sh2 {
			t.Errorf("AddressToScriptHash() not deterministic: %q vs %q", sh1, sh2)
		}
	})

	t.Run("different addresses produce different scripthashes", func(t *testing.T) {
		addr1 := "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
		addr2 := "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
		sh1, _ := AddressToScriptHash(addr1, "mainnet")
		sh2, _ := AddressToScriptHash(addr2, "mainnet")
		if sh1 == sh2 {
			t.Error("AddressToScriptHash() returned same hash for different addresses")
		}
	})
}

func TestValidateAddress(t *testing.T) {
	tests := []struct {
		name    string
		address string
		network string
		wantErr bool
	}{
		{"valid mainnet P2WPKH", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "mainnet", false},
		{"valid mainnet P2WSH", "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", "mainnet", false},
		{"valid testnet4 P2WPKH", "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "testnet4", false},
		{"testnet4 address on mainnet", "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "mainnet", true},
		{"mainnet address on testnet4", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "testnet4", true},
		{"invalid address", "invalid", "mainnet", true},
		{"empty address", "", "mainnet", true},
		{"invalid network", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAddress(tt.address, tt.network)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAddress(%q, %q) error = %v, wantErr %v", tt.address, tt.network, err, tt.wantErr)
			}
		})
	}
}

func TestGetAddressType(t *testing.T) {
	tests := []struct {
		name     string
		address  string
		network  string
		expected string
		wantErr  bool
	}{
		{"P2WPKH mainnet", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "mainnet", "p2wpkh", false},
		{"P2WSH mainnet", "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", "mainnet", "p2wsh", false},
		{"P2WPKH testnet4", "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "testnet4", "p2wpkh", false},
		{"invalid address", "invalid", "mainnet", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addrType, err := GetAddressType(tt.address, tt.network)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAddressType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && addrType != tt.expected {
				t.Errorf("GetAddressType() = %q, want %q", addrType, tt.expected)
			}
		})
	}
}

func TestGenerateAddressInfo(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	t.Run("generates complete address info", func(t *testing.T) {
		info, err := GenerateAddressInfo(seed, "mainnet", 0)
		if err != nil {
			t.Fatalf("GenerateAddressInfo() error = %v", err)
		}

		if info.Address == "" {
			t.Error("GenerateAddressInfo() returned empty address")
		}
		if !strings.HasPrefix(info.Address, "bc1q") {
			t.Errorf("GenerateAddressInfo() address = %q, want bc1q prefix", info.Address)
		}
		if info.Index != 0 {
			t.Errorf("GenerateAddressInfo() index = %d, want 0", info.Index)
		}
		if info.DerivationPath != "m/84'/0'/0'/0/0" {
			t.Errorf("GenerateAddressInfo() path = %q, want m/84'/0'/0'/0/0", info.DerivationPath)
		}
		if len(info.ScriptHash) != 64 {
			t.Errorf("GenerateAddressInfo() scripthash length = %d, want 64", len(info.ScriptHash))
		}
	})

	t.Run("testnet4 info", func(t *testing.T) {
		info, err := GenerateAddressInfo(seed, "testnet4", 5)
		if err != nil {
			t.Fatalf("GenerateAddressInfo() error = %v", err)
		}

		if !strings.HasPrefix(info.Address, "tb1q") {
			t.Errorf("GenerateAddressInfo() address = %q, want tb1q prefix", info.Address)
		}
		if info.Index != 5 {
			t.Errorf("GenerateAddressInfo() index = %d, want 5", info.Index)
		}
		if info.DerivationPath != "m/84'/1'/0'/0/5" {
			t.Errorf("GenerateAddressInfo() path = %q, want m/84'/1'/0'/0/5", info.DerivationPath)
		}
	})
}

func TestGenerateChangeAddressFromSeedForType(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	t.Run("P2WPKH change address generation", func(t *testing.T) {
		addr, err := GenerateChangeAddressFromSeedForType(seed, "mainnet", 0, AddressTypeP2WPKH)
		if err != nil {
			t.Fatalf("GenerateChangeAddressFromSeedForType() error = %v", err)
		}
		if !strings.HasPrefix(addr, "bc1q") {
			t.Errorf("P2WPKH change address should have bc1q prefix, got %q", addr)
		}
	})

	t.Run("P2TR change address generation", func(t *testing.T) {
		addr, err := GenerateChangeAddressFromSeedForType(seed, "mainnet", 0, AddressTypeP2TR)
		if err != nil {
			t.Fatalf("GenerateChangeAddressFromSeedForType() error = %v", err)
		}
		if !strings.HasPrefix(addr, "bc1p") {
			t.Errorf("P2TR change address should have bc1p prefix, got %q", addr)
		}
	})

	t.Run("testnet4 change address", func(t *testing.T) {
		addr, err := GenerateChangeAddressFromSeedForType(seed, "testnet4", 0, AddressTypeP2WPKH)
		if err != nil {
			t.Fatalf("GenerateChangeAddressFromSeedForType() error = %v", err)
		}
		if !strings.HasPrefix(addr, "tb1q") {
			t.Errorf("testnet4 change address should have tb1q prefix, got %q", addr)
		}
	})

	t.Run("change address differs from receiving address", func(t *testing.T) {
		receivingAddr, _ := GenerateAddressFromSeedForType(seed, "mainnet", 0, AddressTypeP2WPKH)
		changeAddr, _ := GenerateChangeAddressFromSeedForType(seed, "mainnet", 0, AddressTypeP2WPKH)

		if receivingAddr == changeAddr {
			t.Error("Change address should differ from receiving address at same index")
		}
	})

	t.Run("different indices produce different change addresses", func(t *testing.T) {
		addr0, _ := GenerateChangeAddressFromSeedForType(seed, "mainnet", 0, AddressTypeP2WPKH)
		addr1, _ := GenerateChangeAddressFromSeedForType(seed, "mainnet", 1, AddressTypeP2WPKH)

		if addr0 == addr1 {
			t.Error("Different indices should produce different change addresses")
		}
	})

	t.Run("same index produces consistent change address", func(t *testing.T) {
		addr1, _ := GenerateChangeAddressFromSeedForType(seed, "mainnet", 5, AddressTypeP2WPKH)
		addr2, _ := GenerateChangeAddressFromSeedForType(seed, "mainnet", 5, AddressTypeP2WPKH)

		if addr1 != addr2 {
			t.Errorf("Same index should produce same change address: %q vs %q", addr1, addr2)
		}
	})

	t.Run("invalid address type fails", func(t *testing.T) {
		_, err := GenerateChangeAddressFromSeedForType(seed, "mainnet", 0, "invalid")
		if err == nil {
			t.Error("GenerateChangeAddressFromSeedForType() should fail for invalid address type")
		}
	})

	t.Run("invalid network fails", func(t *testing.T) {
		_, err := GenerateChangeAddressFromSeedForType(seed, "invalid", 0, AddressTypeP2WPKH)
		if err == nil {
			t.Error("GenerateChangeAddressFromSeedForType() should fail for invalid network")
		}
	})
}

func TestGenerateAddressInfoForType(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	t.Run("P2WPKH address info", func(t *testing.T) {
		info, err := GenerateAddressInfoForType(seed, "mainnet", 0, AddressTypeP2WPKH)
		if err != nil {
			t.Fatalf("GenerateAddressInfoForType() error = %v", err)
		}

		if !strings.HasPrefix(info.Address, "bc1q") {
			t.Errorf("P2WPKH address should have bc1q prefix, got %q", info.Address)
		}
		if info.Index != 0 {
			t.Errorf("Index = %d, want 0", info.Index)
		}
		// BIP84 path for mainnet
		if info.DerivationPath != "m/84'/0'/0'/0/0" {
			t.Errorf("DerivationPath = %q, want m/84'/0'/0'/0/0", info.DerivationPath)
		}
		if len(info.ScriptHash) != 64 {
			t.Errorf("ScriptHash length = %d, want 64", len(info.ScriptHash))
		}
	})

	t.Run("P2TR address info", func(t *testing.T) {
		info, err := GenerateAddressInfoForType(seed, "mainnet", 0, AddressTypeP2TR)
		if err != nil {
			t.Fatalf("GenerateAddressInfoForType() error = %v", err)
		}

		if !strings.HasPrefix(info.Address, "bc1p") {
			t.Errorf("P2TR address should have bc1p prefix, got %q", info.Address)
		}
		// BIP86 path for mainnet
		if info.DerivationPath != "m/86'/0'/0'/0/0" {
			t.Errorf("DerivationPath = %q, want m/86'/0'/0'/0/0", info.DerivationPath)
		}
	})

	t.Run("P2TR testnet4 address info", func(t *testing.T) {
		info, err := GenerateAddressInfoForType(seed, "testnet4", 5, AddressTypeP2TR)
		if err != nil {
			t.Fatalf("GenerateAddressInfoForType() error = %v", err)
		}

		if !strings.HasPrefix(info.Address, "tb1p") {
			t.Errorf("P2TR testnet4 address should have tb1p prefix, got %q", info.Address)
		}
		// BIP86 path for testnet
		if info.DerivationPath != "m/86'/1'/0'/0/5" {
			t.Errorf("DerivationPath = %q, want m/86'/1'/0'/0/5", info.DerivationPath)
		}
		if info.Index != 5 {
			t.Errorf("Index = %d, want 5", info.Index)
		}
	})

	t.Run("different types produce different addresses", func(t *testing.T) {
		p2wpkhInfo, _ := GenerateAddressInfoForType(seed, "mainnet", 0, AddressTypeP2WPKH)
		p2trInfo, _ := GenerateAddressInfoForType(seed, "mainnet", 0, AddressTypeP2TR)

		if p2wpkhInfo.Address == p2trInfo.Address {
			t.Error("P2WPKH and P2TR should produce different addresses")
		}
		if p2wpkhInfo.ScriptHash == p2trInfo.ScriptHash {
			t.Error("P2WPKH and P2TR should produce different scripthashes")
		}
	})
}

func TestGetAddressTypeP2TR(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	t.Run("detects P2TR mainnet address", func(t *testing.T) {
		addr, _ := GenerateAddressFromSeedForType(seed, "mainnet", 0, AddressTypeP2TR)
		addrType, err := GetAddressType(addr, "mainnet")
		if err != nil {
			t.Fatalf("GetAddressType() error = %v", err)
		}
		if addrType != "p2tr" {
			t.Errorf("GetAddressType() = %q, want p2tr", addrType)
		}
	})

	t.Run("detects P2TR testnet address", func(t *testing.T) {
		addr, _ := GenerateAddressFromSeedForType(seed, "testnet4", 0, AddressTypeP2TR)
		addrType, err := GetAddressType(addr, "testnet4")
		if err != nil {
			t.Fatalf("GetAddressType() error = %v", err)
		}
		if addrType != "p2tr" {
			t.Errorf("GetAddressType() = %q, want p2tr", addrType)
		}
	})
}

func TestGetScriptPubKeyP2TR(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	t.Run("P2TR script is correct length", func(t *testing.T) {
		addr, _ := GenerateAddressFromSeedForType(seed, "mainnet", 0, AddressTypeP2TR)
		script, err := GetScriptPubKey(addr, "mainnet")
		if err != nil {
			t.Fatalf("GetScriptPubKey() error = %v", err)
		}
		// P2TR script: OP_1 (0x51) + 32-byte witness program = 34 bytes
		if len(script) != 34 {
			t.Errorf("P2TR script length = %d, want 34", len(script))
		}
		// First byte should be OP_1 (0x51)
		if script[0] != 0x51 {
			t.Errorf("P2TR script should start with OP_1 (0x51), got 0x%02x", script[0])
		}
		// Second byte should be 0x20 (push 32 bytes)
		if script[1] != 0x20 {
			t.Errorf("P2TR script second byte should be 0x20, got 0x%02x", script[1])
		}
	})

	t.Run("P2WPKH script is correct length", func(t *testing.T) {
		addr, _ := GenerateAddressFromSeedForType(seed, "mainnet", 0, AddressTypeP2WPKH)
		script, err := GetScriptPubKey(addr, "mainnet")
		if err != nil {
			t.Fatalf("GetScriptPubKey() error = %v", err)
		}
		// P2WPKH script: OP_0 + 20-byte witness program = 22 bytes
		if len(script) != 22 {
			t.Errorf("P2WPKH script length = %d, want 22", len(script))
		}
	})
}

func TestAddressGenerationBIP84Vectors(t *testing.T) {
	// BIP84 test vectors from the specification
	// Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
	seedHex := "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
	seed, _ := hex.DecodeString(seedHex)

	// Test first address from BIP84 specification
	// Account 0, External chain, Address index 0
	// m/84'/0'/0'/0/0
	t.Run("BIP84 first address", func(t *testing.T) {
		expected := "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
		address, err := GenerateAddressFromSeed(seed, "mainnet", 0)
		if err != nil {
			t.Fatalf("GenerateAddressFromSeed() error = %v", err)
		}
		if address != expected {
			t.Errorf("BIP84 vector mismatch:\ngot:  %s\nwant: %s", address, expected)
		}
	})

	// Test that subsequent addresses are different
	t.Run("subsequent addresses differ", func(t *testing.T) {
		addr0, _ := GenerateAddressFromSeed(seed, "mainnet", 0)
		addr1, _ := GenerateAddressFromSeed(seed, "mainnet", 1)
		addr2, _ := GenerateAddressFromSeed(seed, "mainnet", 2)

		if addr0 == addr1 || addr1 == addr2 || addr0 == addr2 {
			t.Error("Subsequent addresses should be unique")
		}

		// All should start with bc1q for native SegWit
		for i, addr := range []string{addr0, addr1, addr2} {
			if !strings.HasPrefix(addr, "bc1q") {
				t.Errorf("Address %d should start with bc1q, got: %s", i, addr)
			}
		}
	})
}
