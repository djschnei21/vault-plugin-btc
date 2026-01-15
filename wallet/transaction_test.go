package wallet

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestSelectUTXOs(t *testing.T) {
	tests := []struct {
		name         string
		utxos        []UTXO
		targetAmount int64
		feeRate      int64
		wantErr      bool
		wantCount    int
	}{
		{
			name: "single UTXO sufficient",
			utxos: []UTXO{
				{TxID: "abc", Vout: 0, Value: 100000},
			},
			targetAmount: 50000,
			feeRate:      10,
			wantErr:      false,
			wantCount:    1,
		},
		{
			name: "multiple UTXOs needed",
			utxos: []UTXO{
				{TxID: "abc", Vout: 0, Value: 30000},
				{TxID: "def", Vout: 0, Value: 30000},
				{TxID: "ghi", Vout: 0, Value: 30000},
			},
			targetAmount: 50000,
			feeRate:      10,
			wantErr:      false,
			wantCount:    2, // Should select 2 largest
		},
		{
			name: "selects largest first",
			utxos: []UTXO{
				{TxID: "small1", Vout: 0, Value: 10000},
				{TxID: "large", Vout: 0, Value: 100000},
				{TxID: "small2", Vout: 0, Value: 10000},
			},
			targetAmount: 50000,
			feeRate:      10,
			wantErr:      false,
			wantCount:    1, // Should select the large one
		},
		{
			name:         "empty UTXOs",
			utxos:        []UTXO{},
			targetAmount: 50000,
			feeRate:      10,
			wantErr:      true,
		},
		{
			name: "insufficient funds",
			utxos: []UTXO{
				{TxID: "abc", Vout: 0, Value: 1000},
			},
			targetAmount: 50000,
			feeRate:      10,
			wantErr:      true,
		},
		{
			name: "exact amount with fee",
			utxos: []UTXO{
				{TxID: "abc", Vout: 0, Value: 52000}, // Just enough for 50000 + ~1400 fee
			},
			targetAmount: 50000,
			feeRate:      10,
			wantErr:      false,
			wantCount:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selected, fee, err := SelectUTXOs(tt.utxos, tt.targetAmount, tt.feeRate)
			if (err != nil) != tt.wantErr {
				t.Errorf("SelectUTXOs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(selected) != tt.wantCount {
					t.Errorf("SelectUTXOs() selected %d UTXOs, want %d", len(selected), tt.wantCount)
				}
				if fee <= 0 {
					t.Errorf("SelectUTXOs() fee = %d, want > 0", fee)
				}

				// Verify selected UTXOs have sufficient value
				var totalValue int64
				for _, utxo := range selected {
					totalValue += utxo.Value
				}
				if totalValue < tt.targetAmount+fee {
					t.Errorf("SelectUTXOs() total value %d < target %d + fee %d",
						totalValue, tt.targetAmount, fee)
				}
			}
		})
	}
}

func TestEstimateFee(t *testing.T) {
	tests := []struct {
		name       string
		numInputs  int
		numOutputs int
		feeRate    int64
		wantMin    int64
		wantMax    int64
	}{
		{
			name:       "1 input 1 output",
			numInputs:  1,
			numOutputs: 1,
			feeRate:    10,
			wantMin:    500,  // At least 50 vbytes * 10 sat/vbyte
			wantMax:    2000, // At most 200 vbytes * 10 sat/vbyte
		},
		{
			name:       "1 input 2 outputs",
			numInputs:  1,
			numOutputs: 2,
			feeRate:    10,
			wantMin:    500,
			wantMax:    2500,
		},
		{
			name:       "2 inputs 2 outputs",
			numInputs:  2,
			numOutputs: 2,
			feeRate:    10,
			wantMin:    1000,
			wantMax:    3500,
		},
		{
			name:       "high fee rate",
			numInputs:  1,
			numOutputs: 2,
			feeRate:    100,
			wantMin:    5000,
			wantMax:    25000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fee := EstimateTransactionFee(tt.numInputs, tt.numOutputs, tt.feeRate)
			if fee < tt.wantMin || fee > tt.wantMax {
				t.Errorf("EstimateTransactionFee() = %d, want between %d and %d",
					fee, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestBuildTransaction(t *testing.T) {
	// Use BIP84 test seed for deterministic testing
	seedHex := "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
	seed, _ := hex.DecodeString(seedHex)

	// Generate address info to get the scriptPubKey
	addrInfo, err := GenerateAddressInfo(seed, "mainnet", 0)
	if err != nil {
		t.Fatalf("GenerateAddressInfo() error = %v", err)
	}

	scriptPubKey, err := GetScriptPubKey(addrInfo.Address, "mainnet")
	if err != nil {
		t.Fatalf("GetScriptPubKey() error = %v", err)
	}

	// Create a mock UTXO
	utxos := []UTXO{
		{
			TxID:         "0000000000000000000000000000000000000000000000000000000000000001",
			Vout:         0,
			Value:        100000, // 0.001 BTC
			Address:      addrInfo.Address,
			AddressIndex: 0,
			ScriptPubKey: scriptPubKey,
		},
	}

	// Destination address (another valid mainnet address)
	destAddress := "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"

	outputs := []TxOutput{
		{
			Address: destAddress,
			Value:   50000, // 0.0005 BTC
		},
	}

	changeAddress := addrInfo.Address

	t.Run("builds valid transaction", func(t *testing.T) {
		result, err := BuildTransaction(seed, "mainnet", utxos, outputs, changeAddress, 10)
		if err != nil {
			t.Fatalf("BuildTransaction() error = %v", err)
		}

		if result.TxID == "" {
			t.Error("BuildTransaction() returned empty TxID")
		}
		if result.Hex == "" {
			t.Error("BuildTransaction() returned empty Hex")
		}
		if result.Fee <= 0 {
			t.Errorf("BuildTransaction() fee = %d, want > 0", result.Fee)
		}
		if result.TotalInput != 100000 {
			t.Errorf("BuildTransaction() total input = %d, want 100000", result.TotalInput)
		}
		if result.TotalOutput != 50000 {
			t.Errorf("BuildTransaction() total output = %d, want 50000", result.TotalOutput)
		}

		// Change should be input - output - fee
		expectedChange := result.TotalInput - result.TotalOutput - result.Fee
		if result.ChangeAmount > 0 && result.ChangeAmount != expectedChange {
			t.Errorf("BuildTransaction() change = %d, want %d", result.ChangeAmount, expectedChange)
		}

		// Verify Hex is valid hex
		_, err = hex.DecodeString(result.Hex)
		if err != nil {
			t.Errorf("BuildTransaction() Hex is not valid hex: %v", err)
		}
	})

	t.Run("fails for dust output", func(t *testing.T) {
		dustOutputs := []TxOutput{
			{
				Address: destAddress,
				Value:   100, // Below dust limit
			},
		}

		_, err := BuildTransaction(seed, "mainnet", utxos, dustOutputs, changeAddress, 10)
		if err == nil {
			t.Error("BuildTransaction() should fail for dust output")
		}
	})

	t.Run("fails for insufficient funds", func(t *testing.T) {
		bigOutputs := []TxOutput{
			{
				Address: destAddress,
				Value:   200000, // More than available
			},
		}

		_, err := BuildTransaction(seed, "mainnet", utxos, bigOutputs, changeAddress, 10)
		if err == nil {
			t.Error("BuildTransaction() should fail for insufficient funds")
		}
	})

	t.Run("fails for invalid destination address", func(t *testing.T) {
		invalidOutputs := []TxOutput{
			{
				Address: "invalid",
				Value:   50000,
			},
		}

		_, err := BuildTransaction(seed, "mainnet", utxos, invalidOutputs, changeAddress, 10)
		if err == nil {
			t.Error("BuildTransaction() should fail for invalid address")
		}
	})

	t.Run("fails for invalid change address", func(t *testing.T) {
		_, err := BuildTransaction(seed, "mainnet", utxos, outputs, "invalid", 10)
		if err == nil {
			t.Error("BuildTransaction() should fail for invalid change address")
		}
	})

	t.Run("fails for invalid UTXO txid", func(t *testing.T) {
		badUtxos := []UTXO{
			{
				TxID:         "invalid",
				Vout:         0,
				Value:        100000,
				Address:      addrInfo.Address,
				AddressIndex: 0,
				ScriptPubKey: scriptPubKey,
			},
		}

		_, err := BuildTransaction(seed, "mainnet", badUtxos, outputs, changeAddress, 10)
		if err == nil {
			t.Error("BuildTransaction() should fail for invalid UTXO txid")
		}
	})
}

func TestBuildTransactionTestnet(t *testing.T) {
	seedHex := "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
	seed, _ := hex.DecodeString(seedHex)

	addrInfo, err := GenerateAddressInfo(seed, "testnet4", 0)
	if err != nil {
		t.Fatalf("GenerateAddressInfo() error = %v", err)
	}

	scriptPubKey, err := GetScriptPubKey(addrInfo.Address, "testnet4")
	if err != nil {
		t.Fatalf("GetScriptPubKey() error = %v", err)
	}

	utxos := []UTXO{
		{
			TxID:         "0000000000000000000000000000000000000000000000000000000000000001",
			Vout:         0,
			Value:        100000,
			Address:      addrInfo.Address,
			AddressIndex: 0,
			ScriptPubKey: scriptPubKey,
		},
	}

	// Testnet destination address
	destAddress := "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"

	outputs := []TxOutput{
		{
			Address: destAddress,
			Value:   50000,
		},
	}

	t.Run("builds testnet4 transaction", func(t *testing.T) {
		result, err := BuildTransaction(seed, "testnet4", utxos, outputs, addrInfo.Address, 10)
		if err != nil {
			t.Fatalf("BuildTransaction() error = %v", err)
		}

		if result.TxID == "" {
			t.Error("BuildTransaction() returned empty TxID")
		}
	})
}

func TestBuildTransactionMultipleInputs(t *testing.T) {
	seedHex := "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
	seed, _ := hex.DecodeString(seedHex)

	// Create UTXOs from different address indices
	var utxos []UTXO
	for i := uint32(0); i < 3; i++ {
		addrInfo, err := GenerateAddressInfo(seed, "mainnet", i)
		if err != nil {
			t.Fatalf("GenerateAddressInfo() error = %v", err)
		}

		scriptPubKey, err := GetScriptPubKey(addrInfo.Address, "mainnet")
		if err != nil {
			t.Fatalf("GetScriptPubKey() error = %v", err)
		}

		utxos = append(utxos, UTXO{
			TxID:         "000000000000000000000000000000000000000000000000000000000000000" + string(rune('1'+i)),
			Vout:         0,
			Value:        30000, // 0.0003 BTC each
			Address:      addrInfo.Address,
			AddressIndex: i,
			ScriptPubKey: scriptPubKey,
		})
	}

	destAddress := "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	changeAddrInfo, _ := GenerateAddressInfo(seed, "mainnet", 10)

	outputs := []TxOutput{
		{
			Address: destAddress,
			Value:   50000, // Requires at least 2 UTXOs
		},
	}

	t.Run("builds transaction with multiple inputs", func(t *testing.T) {
		result, err := BuildTransaction(seed, "mainnet", utxos[:2], outputs, changeAddrInfo.Address, 10)
		if err != nil {
			t.Fatalf("BuildTransaction() error = %v", err)
		}

		if result.TotalInput != 60000 {
			t.Errorf("BuildTransaction() total input = %d, want 60000", result.TotalInput)
		}
	})
}

func TestDustLimit(t *testing.T) {
	if DustLimit <= 0 {
		t.Errorf("DustLimit = %d, want > 0", DustLimit)
	}
	// Standard dust limit for P2WPKH is 546 satoshis
	if DustLimit != 546 {
		t.Errorf("DustLimit = %d, want 546 for P2WPKH", DustLimit)
	}
}

func TestTransactionSizes(t *testing.T) {
	// P2WPKH input should be approximately 68 vbytes
	if P2WPKHInputSize < 60 || P2WPKHInputSize > 80 {
		t.Errorf("P2WPKHInputSize = %d, expected ~68", P2WPKHInputSize)
	}

	// P2WPKH output should be approximately 31 bytes
	if P2WPKHOutputSize < 25 || P2WPKHOutputSize > 35 {
		t.Errorf("P2WPKHOutputSize = %d, expected ~31", P2WPKHOutputSize)
	}

	// Transaction overhead should be approximately 10-11 bytes
	if TxOverhead < 10 || TxOverhead > 15 {
		t.Errorf("TxOverhead = %d, expected ~10-11", TxOverhead)
	}
}

func TestSelectUTXOsOrdering(t *testing.T) {
	// Verify that largest UTXOs are selected first
	utxos := []UTXO{
		{TxID: "small", Vout: 0, Value: 1000},
		{TxID: "large", Vout: 0, Value: 100000},
		{TxID: "medium", Vout: 0, Value: 50000},
	}

	selected, _, err := SelectUTXOs(utxos, 40000, 10)
	if err != nil {
		t.Fatalf("SelectUTXOs() error = %v", err)
	}

	// Should select the large one first (100000 > 40000 + fee)
	if len(selected) != 1 {
		t.Errorf("SelectUTXOs() selected %d UTXOs, want 1", len(selected))
	}
	if selected[0].TxID != "large" {
		t.Errorf("SelectUTXOs() selected UTXO %q, want 'large'", selected[0].TxID)
	}
}

func TestValidateFeeRate(t *testing.T) {
	tests := []struct {
		name    string
		feeRate int64
		wantErr bool
	}{
		{"normal fee rate 1", 1, false},
		{"normal fee rate 10", 10, false},
		{"normal fee rate 100", 100, false},
		{"at limit", MaxReasonableFeeRate, false},
		{"above limit", MaxReasonableFeeRate + 1, true},
		{"very high", 10000, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errMsg := ValidateFeeRate(tt.feeRate)
			gotErr := errMsg != ""
			if gotErr != tt.wantErr {
				t.Errorf("ValidateFeeRate(%d) returned error = %v, wantErr %v (msg: %s)",
					tt.feeRate, gotErr, tt.wantErr, errMsg)
			}
		})
	}
}

func TestIsFeeRateUnreasonable(t *testing.T) {
	tests := []struct {
		name             string
		feeRate          int64
		wantUnreasonable bool
	}{
		{"low fee rate", 1, false},
		{"normal fee rate", 50, false},
		{"high but acceptable", 500, false},
		{"at limit", MaxReasonableFeeRate, false},
		{"just above limit", MaxReasonableFeeRate + 1, true},
		{"very high", 5000, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsFeeRateUnreasonable(tt.feeRate)
			if result != tt.wantUnreasonable {
				t.Errorf("IsFeeRateUnreasonable(%d) = %v, want %v",
					tt.feeRate, result, tt.wantUnreasonable)
			}
		})
	}
}

func TestEstimateFeeForTypes(t *testing.T) {
	tests := []struct {
		name       string
		numInputs  int
		numOutputs int
		feeRate    int64
		inputType  string
		outputType string
		wantMin    int64
		wantMax    int64
	}{
		{
			name:       "P2WPKH inputs and outputs",
			numInputs:  1,
			numOutputs: 2,
			feeRate:    10,
			inputType:  AddressTypeP2WPKH,
			outputType: AddressTypeP2WPKH,
			wantMin:    500,
			wantMax:    1500,
		},
		{
			name:       "P2TR inputs and outputs",
			numInputs:  1,
			numOutputs: 2,
			feeRate:    10,
			inputType:  AddressTypeP2TR,
			outputType: AddressTypeP2TR,
			wantMin:    500,
			wantMax:    1600, // P2TR has larger outputs
		},
		{
			name:       "P2TR inputs, P2WPKH outputs",
			numInputs:  2,
			numOutputs: 2,
			feeRate:    10,
			inputType:  AddressTypeP2TR,
			outputType: AddressTypeP2WPKH,
			wantMin:    700,
			wantMax:    2000,
		},
		{
			name:       "empty input type defaults to P2WPKH",
			numInputs:  1,
			numOutputs: 1,
			feeRate:    10,
			inputType:  "",
			outputType: "",
			wantMin:    500,
			wantMax:    1200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fee := EstimateFeeForTypes(tt.numInputs, tt.numOutputs, tt.feeRate, tt.inputType, tt.outputType)
			if fee < tt.wantMin || fee > tt.wantMax {
				t.Errorf("EstimateFeeForTypes() = %d, want between %d and %d",
					fee, tt.wantMin, tt.wantMax)
			}
		})
	}

	t.Run("P2TR inputs are smaller than P2WPKH", func(t *testing.T) {
		p2wpkhFee := EstimateFeeForTypes(1, 1, 10, AddressTypeP2WPKH, AddressTypeP2WPKH)
		p2trFee := EstimateFeeForTypes(1, 1, 10, AddressTypeP2TR, AddressTypeP2TR)
		// P2TR inputs are smaller (58 vs 68 vbytes) but outputs are larger (43 vs 31 bytes)
		// With 1 input and 1 output, the difference should exist
		if p2wpkhFee == p2trFee {
			t.Errorf("P2WPKH and P2TR fees should differ, both are %d", p2wpkhFee)
		}
	})
}

func TestEstimateFeeForUTXOs(t *testing.T) {
	t.Run("mixed address types", func(t *testing.T) {
		utxos := []UTXO{
			{TxID: "a", Value: 10000, AddressType: AddressTypeP2WPKH},
			{TxID: "b", Value: 20000, AddressType: AddressTypeP2TR},
			{TxID: "c", Value: 30000, AddressType: AddressTypeP2WPKH},
		}

		fee := EstimateFeeForUTXOs(utxos, 2, 10, AddressTypeP2WPKH)

		// Expected: overhead(10) + 68 + 58 + 68 + 2*31 = 10 + 194 + 62 = 266 vbytes
		// At 10 sat/vB = ~2660 satoshis
		expectedMin := int64(2000)
		expectedMax := int64(3000)
		if fee < expectedMin || fee > expectedMax {
			t.Errorf("EstimateFeeForUTXOs() = %d, want between %d and %d", fee, expectedMin, expectedMax)
		}
	})

	t.Run("all P2TR", func(t *testing.T) {
		utxos := []UTXO{
			{TxID: "a", Value: 10000, AddressType: AddressTypeP2TR},
			{TxID: "b", Value: 20000, AddressType: AddressTypeP2TR},
		}

		fee := EstimateFeeForUTXOs(utxos, 1, 10, AddressTypeP2TR)

		// Expected: overhead(10) + 2*58 + 1*43 = 10 + 116 + 43 = 169 vbytes
		// At 10 sat/vB = 1690 satoshis
		expectedMin := int64(1500)
		expectedMax := int64(2000)
		if fee < expectedMin || fee > expectedMax {
			t.Errorf("EstimateFeeForUTXOs() = %d, want between %d and %d", fee, expectedMin, expectedMax)
		}
	})

	t.Run("empty address type defaults to P2WPKH", func(t *testing.T) {
		utxos := []UTXO{
			{TxID: "a", Value: 10000, AddressType: ""},
		}

		feeEmpty := EstimateFeeForUTXOs(utxos, 1, 10, "")

		utxosP2WPKH := []UTXO{
			{TxID: "a", Value: 10000, AddressType: AddressTypeP2WPKH},
		}
		feeP2WPKH := EstimateFeeForUTXOs(utxosP2WPKH, 1, 10, AddressTypeP2WPKH)

		if feeEmpty != feeP2WPKH {
			t.Errorf("Empty address type should default to P2WPKH: got %d, want %d", feeEmpty, feeP2WPKH)
		}
	})
}

func TestFeeCalculation(t *testing.T) {
	seedHex := "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
	seed, _ := hex.DecodeString(seedHex)

	addrInfo, _ := GenerateAddressInfo(seed, "mainnet", 0)
	scriptPubKey, _ := GetScriptPubKey(addrInfo.Address, "mainnet")

	utxos := []UTXO{
		{
			TxID:         "0000000000000000000000000000000000000000000000000000000000000001",
			Vout:         0,
			Value:        100000,
			Address:      addrInfo.Address,
			AddressIndex: 0,
			ScriptPubKey: scriptPubKey,
		},
	}

	destAddress := "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	outputs := []TxOutput{{Address: destAddress, Value: 50000}}

	// Test different fee rates
	feeRates := []int64{1, 10, 50, 100}

	var prevFee int64 = 0
	for _, feeRate := range feeRates {
		feeRate := feeRate // capture for closure
		t.Run(fmt.Sprintf("fee rate %d", feeRate), func(t *testing.T) {
			result, err := BuildTransaction(seed, "mainnet", utxos, outputs, addrInfo.Address, feeRate)
			if err != nil {
				t.Fatalf("BuildTransaction() error = %v", err)
			}

			// Fee should increase with fee rate
			if feeRate > 1 && result.Fee <= prevFee {
				t.Errorf("Fee %d should be > previous fee %d at higher fee rate", result.Fee, prevFee)
			}
			prevFee = result.Fee

			// Fee should be roughly proportional to fee rate
			expectedMinFee := feeRate * 100 // At least 100 vbytes
			if result.Fee < expectedMinFee {
				t.Errorf("Fee %d seems too low for fee rate %d", result.Fee, feeRate)
			}
		})
	}
}

func TestBuildConsolidationTransaction(t *testing.T) {
	seedHex := "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
	seed, _ := hex.DecodeString(seedHex)

	// Generate addresses and create UTXOs
	makeUTXO := func(index uint32, value int64) UTXO {
		addrInfo, _ := GenerateAddressInfo(seed, "mainnet", index)
		scriptPubKey, _ := GetScriptPubKey(addrInfo.Address, "mainnet")
		return UTXO{
			TxID:         fmt.Sprintf("000000000000000000000000000000000000000000000000000000000000000%d", index+1),
			Vout:         0,
			Value:        value,
			Address:      addrInfo.Address,
			AddressIndex: index,
			ScriptPubKey: scriptPubKey,
			AddressType:  AddressTypeP2WPKH,
		}
	}

	destAddrInfo, _ := GenerateAddressInfo(seed, "mainnet", 10)

	t.Run("builds valid consolidation transaction", func(t *testing.T) {
		utxos := []UTXO{
			makeUTXO(0, 50000),
			makeUTXO(1, 30000),
		}

		result, err := BuildConsolidationTransaction(seed, "mainnet", utxos, destAddrInfo.Address, 10)
		if err != nil {
			t.Fatalf("BuildConsolidationTransaction() error = %v", err)
		}

		if result.TxID == "" {
			t.Error("BuildConsolidationTransaction() returned empty TxID")
		}
		if result.Hex == "" {
			t.Error("BuildConsolidationTransaction() returned empty Hex")
		}
		if result.TotalInput != 80000 {
			t.Errorf("BuildConsolidationTransaction() total input = %d, want 80000", result.TotalInput)
		}
		if result.ChangeAmount != 0 {
			t.Errorf("BuildConsolidationTransaction() change = %d, want 0", result.ChangeAmount)
		}
		if result.Fee <= 0 {
			t.Errorf("BuildConsolidationTransaction() fee = %d, want > 0", result.Fee)
		}
		// Output should be input minus fee
		expectedOutput := result.TotalInput - result.Fee
		if result.TotalOutput != expectedOutput {
			t.Errorf("BuildConsolidationTransaction() output = %d, want %d", result.TotalOutput, expectedOutput)
		}
	})

	t.Run("fails with less than 2 UTXOs", func(t *testing.T) {
		utxos := []UTXO{makeUTXO(0, 50000)}

		_, err := BuildConsolidationTransaction(seed, "mainnet", utxos, destAddrInfo.Address, 10)
		if err == nil {
			t.Error("BuildConsolidationTransaction() should fail with only 1 UTXO")
		}
	})

	t.Run("fails with insufficient funds for fee", func(t *testing.T) {
		// Very small UTXOs that can't cover the fee
		utxos := []UTXO{
			makeUTXO(0, 100),
			makeUTXO(1, 100),
		}

		_, err := BuildConsolidationTransaction(seed, "mainnet", utxos, destAddrInfo.Address, 100)
		if err == nil {
			t.Error("BuildConsolidationTransaction() should fail with insufficient funds")
		}
	})

	t.Run("fails with invalid destination address", func(t *testing.T) {
		utxos := []UTXO{
			makeUTXO(0, 50000),
			makeUTXO(1, 30000),
		}

		_, err := BuildConsolidationTransaction(seed, "mainnet", utxos, "invalid", 10)
		if err == nil {
			t.Error("BuildConsolidationTransaction() should fail with invalid address")
		}
	})

	t.Run("fails with invalid network", func(t *testing.T) {
		utxos := []UTXO{
			makeUTXO(0, 50000),
			makeUTXO(1, 30000),
		}

		_, err := BuildConsolidationTransaction(seed, "invalid", utxos, destAddrInfo.Address, 10)
		if err == nil {
			t.Error("BuildConsolidationTransaction() should fail with invalid network")
		}
	})

	t.Run("consolidates many UTXOs", func(t *testing.T) {
		var utxos []UTXO
		for i := uint32(0); i < 5; i++ {
			utxos = append(utxos, makeUTXO(i, 20000))
		}

		result, err := BuildConsolidationTransaction(seed, "mainnet", utxos, destAddrInfo.Address, 10)
		if err != nil {
			t.Fatalf("BuildConsolidationTransaction() error = %v", err)
		}

		if result.TotalInput != 100000 {
			t.Errorf("BuildConsolidationTransaction() total input = %d, want 100000", result.TotalInput)
		}
	})
}

func TestBuildConsolidationTransactionP2TR(t *testing.T) {
	seedHex := "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
	seed, _ := hex.DecodeString(seedHex)

	// Generate P2TR addresses and UTXOs
	makeP2TRUTXO := func(index uint32, value int64) UTXO {
		addrInfo, _ := GenerateAddressInfoForType(seed, "mainnet", index, AddressTypeP2TR)
		scriptPubKey, _ := GetScriptPubKey(addrInfo.Address, "mainnet")
		return UTXO{
			TxID:         fmt.Sprintf("000000000000000000000000000000000000000000000000000000000000000%d", index+1),
			Vout:         0,
			Value:        value,
			Address:      addrInfo.Address,
			AddressIndex: index,
			ScriptPubKey: scriptPubKey,
			AddressType:  AddressTypeP2TR,
		}
	}

	destAddrInfo, _ := GenerateAddressInfoForType(seed, "mainnet", 10, AddressTypeP2TR)

	t.Run("builds valid P2TR consolidation", func(t *testing.T) {
		utxos := []UTXO{
			makeP2TRUTXO(0, 50000),
			makeP2TRUTXO(1, 30000),
		}

		result, err := BuildConsolidationTransaction(seed, "mainnet", utxos, destAddrInfo.Address, 10)
		if err != nil {
			t.Fatalf("BuildConsolidationTransaction() error = %v", err)
		}

		if result.TxID == "" {
			t.Error("BuildConsolidationTransaction() returned empty TxID")
		}
		if result.TotalInput != 80000 {
			t.Errorf("BuildConsolidationTransaction() total input = %d, want 80000", result.TotalInput)
		}
	})
}

func TestBuildTransactionP2TR(t *testing.T) {
	seedHex := "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
	seed, _ := hex.DecodeString(seedHex)

	// Generate P2TR address info
	addrInfo, err := GenerateAddressInfoForType(seed, "mainnet", 0, AddressTypeP2TR)
	if err != nil {
		t.Fatalf("GenerateAddressInfoForType() error = %v", err)
	}

	scriptPubKey, err := GetScriptPubKey(addrInfo.Address, "mainnet")
	if err != nil {
		t.Fatalf("GetScriptPubKey() error = %v", err)
	}

	// Create a mock UTXO with P2TR type
	utxos := []UTXO{
		{
			TxID:         "0000000000000000000000000000000000000000000000000000000000000001",
			Vout:         0,
			Value:        100000,
			Address:      addrInfo.Address,
			AddressIndex: 0,
			ScriptPubKey: scriptPubKey,
			AddressType:  AddressTypeP2TR,
		},
	}

	// Destination address (P2TR)
	destAddrInfo, _ := GenerateAddressInfoForType(seed, "mainnet", 1, AddressTypeP2TR)

	outputs := []TxOutput{
		{
			Address: destAddrInfo.Address,
			Value:   50000,
		},
	}

	changeAddrInfo, _ := GenerateAddressInfoForType(seed, "mainnet", 10, AddressTypeP2TR)

	t.Run("builds valid P2TR transaction", func(t *testing.T) {
		result, err := BuildTransaction(seed, "mainnet", utxos, outputs, changeAddrInfo.Address, 10)
		if err != nil {
			t.Fatalf("BuildTransaction() error = %v", err)
		}

		if result.TxID == "" {
			t.Error("BuildTransaction() returned empty TxID")
		}
		if result.Hex == "" {
			t.Error("BuildTransaction() returned empty Hex")
		}
		if result.Fee <= 0 {
			t.Errorf("BuildTransaction() fee = %d, want > 0", result.Fee)
		}

		// Verify Hex is valid hex
		_, err = hex.DecodeString(result.Hex)
		if err != nil {
			t.Errorf("BuildTransaction() Hex is not valid hex: %v", err)
		}
	})

	t.Run("P2TR address prefix is bc1p", func(t *testing.T) {
		if addrInfo.Address[:4] != "bc1p" {
			t.Errorf("P2TR address should start with bc1p, got %s", addrInfo.Address[:4])
		}
	})
}

func TestBuildTransactionMixedInputTypes(t *testing.T) {
	seedHex := "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
	seed, _ := hex.DecodeString(seedHex)

	// Create P2WPKH UTXO
	p2wpkhInfo, _ := GenerateAddressInfo(seed, "mainnet", 0)
	p2wpkhScript, _ := GetScriptPubKey(p2wpkhInfo.Address, "mainnet")

	// Create P2TR UTXO
	p2trInfo, _ := GenerateAddressInfoForType(seed, "mainnet", 1, AddressTypeP2TR)
	p2trScript, _ := GetScriptPubKey(p2trInfo.Address, "mainnet")

	utxos := []UTXO{
		{
			TxID:         "0000000000000000000000000000000000000000000000000000000000000001",
			Vout:         0,
			Value:        50000,
			Address:      p2wpkhInfo.Address,
			AddressIndex: 0,
			ScriptPubKey: p2wpkhScript,
			AddressType:  AddressTypeP2WPKH,
		},
		{
			TxID:         "0000000000000000000000000000000000000000000000000000000000000002",
			Vout:         0,
			Value:        50000,
			Address:      p2trInfo.Address,
			AddressIndex: 1,
			ScriptPubKey: p2trScript,
			AddressType:  AddressTypeP2TR,
		},
	}

	destAddr := "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	changeAddr, _ := GenerateAddressFromSeed(seed, "mainnet", 10)

	outputs := []TxOutput{
		{Address: destAddr, Value: 50000},
	}

	t.Run("handles mixed P2WPKH and P2TR inputs", func(t *testing.T) {
		result, err := BuildTransaction(seed, "mainnet", utxos, outputs, changeAddr, 10)
		if err != nil {
			t.Fatalf("BuildTransaction() error = %v", err)
		}

		if result.TxID == "" {
			t.Error("BuildTransaction() returned empty TxID")
		}
		if result.TotalInput != 100000 {
			t.Errorf("BuildTransaction() total input = %d, want 100000", result.TotalInput)
		}
	})
}

func TestRBFSequenceNumbers(t *testing.T) {
	t.Run("RBF sequence constant is correct", func(t *testing.T) {
		// BIP125 specifies sequence < 0xFFFFFFFE signals opt-in RBF
		if SequenceRBF >= 0xFFFFFFFE {
			t.Errorf("SequenceRBF = 0x%X, should be < 0xFFFFFFFE for RBF", SequenceRBF)
		}
		// Standard RBF sequence is 0xFFFFFFFD
		if SequenceRBF != 0xFFFFFFFD {
			t.Errorf("SequenceRBF = 0x%X, want 0xFFFFFFFD", SequenceRBF)
		}
	})

	t.Run("Final sequence constant is correct", func(t *testing.T) {
		if SequenceFinal != 0xFFFFFFFF {
			t.Errorf("SequenceFinal = 0x%X, want 0xFFFFFFFF", SequenceFinal)
		}
	})
}

func TestTransactionSizesP2TR(t *testing.T) {
	// P2TR input should be smaller than P2WPKH (due to Schnorr signature)
	if P2TRInputSize >= P2WPKHInputSize {
		t.Errorf("P2TRInputSize (%d) should be < P2WPKHInputSize (%d)", P2TRInputSize, P2WPKHInputSize)
	}

	// P2TR output should be larger than P2WPKH (32-byte vs 20-byte witness program)
	if P2TROutputSize <= P2WPKHOutputSize {
		t.Errorf("P2TROutputSize (%d) should be > P2WPKHOutputSize (%d)", P2TROutputSize, P2WPKHOutputSize)
	}

	// P2TR input should be approximately 58 vbytes
	if P2TRInputSize < 55 || P2TRInputSize > 65 {
		t.Errorf("P2TRInputSize = %d, expected ~58", P2TRInputSize)
	}

	// P2TR output should be approximately 43 bytes
	if P2TROutputSize < 40 || P2TROutputSize > 46 {
		t.Errorf("P2TROutputSize = %d, expected ~43", P2TROutputSize)
	}
}
