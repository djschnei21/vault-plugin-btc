package wallet

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// UTXO represents an unspent transaction output for transaction building
type UTXO struct {
	TxID         string
	Vout         int
	Value        int64
	Address      string
	AddressIndex uint32
	ScriptPubKey []byte
	AddressType  string // p2wpkh or p2tr - determines signing method
}

// TxOutput represents a transaction output
type TxOutput struct {
	Address string
	Value   int64
}

// TransactionResult contains the result of building a transaction
type TransactionResult struct {
	TxID         string
	Hex          string
	Fee          int64
	TotalInput   int64
	TotalOutput  int64
	ChangeAmount int64
	Size         int
	VSize        int
}

const (
	// DustLimit is the minimum output value (546 satoshis for P2WPKH)
	DustLimit = 546

	// DefaultFeeRate in satoshis per vbyte
	DefaultFeeRate = 10

	// P2WPKHInputSize is the virtual size of a P2WPKH input in vbytes
	// witness data is discounted
	P2WPKHInputSize = 68

	// P2WPKHOutputSize is the size of a P2WPKH output in bytes
	P2WPKHOutputSize = 31

	// P2TRInputSize is the virtual size of a P2TR key-path input in vbytes
	// Taproot witness: 1 byte count + 64 byte Schnorr signature = 65 bytes
	// Witness discount: 65/4 = 16.25 -> ~17 vbytes for witness
	// Non-witness: 32 (outpoint) + 4 (sequence) + 1 (script length) = 37 bytes
	// Total: 37 + 17 = ~57.5 vbytes (we use 58)
	P2TRInputSize = 58

	// P2TROutputSize is the size of a P2TR output in bytes
	// 8 (value) + 1 (script length) + 34 (OP_1 + 32-byte witness program) = 43 bytes
	P2TROutputSize = 43

	// TxOverhead is the base transaction overhead
	TxOverhead = 10

	// MaxReasonableFeeRate is the maximum fee rate (sat/vB) before requiring confirmation
	// 1000 sat/vB is extremely high - even during peak congestion fees rarely exceed 500
	MaxReasonableFeeRate = 1000

	// SequenceRBF is the sequence number that enables Replace-By-Fee (BIP125)
	// 0xFFFFFFFD signals opt-in RBF, allowing fee bumping of stuck transactions
	SequenceRBF = 0xFFFFFFFD

	// SequenceFinal is the final sequence number (no RBF, default in many implementations)
	SequenceFinal = 0xFFFFFFFF
)

// ValidateFeeRate checks if the fee rate is within reasonable bounds
// Returns an error message if the fee rate is dangerously high, empty string otherwise
func ValidateFeeRate(feeRate int64) string {
	if feeRate > MaxReasonableFeeRate {
		return fmt.Sprintf("fee_rate %d sat/vB exceeds safety limit of %d sat/vB - this would be extremely expensive", feeRate, MaxReasonableFeeRate)
	}
	return ""
}

// IsFeeRateUnreasonable returns true if the fee rate exceeds safety limits
func IsFeeRateUnreasonable(feeRate int64) bool {
	return feeRate > MaxReasonableFeeRate
}

// SelectUTXOs selects UTXOs to cover the target amount plus fee
// Uses a simple "largest first" strategy
func SelectUTXOs(utxos []UTXO, targetAmount int64, feeRate int64) ([]UTXO, int64, error) {
	if len(utxos) == 0 {
		return nil, 0, fmt.Errorf("no UTXOs available")
	}

	// Sort UTXOs by value (largest first)
	sorted := make([]UTXO, len(utxos))
	copy(sorted, utxos)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value > sorted[j].Value
	})

	var selected []UTXO
	var totalInput int64

	// Estimate initial fee (1 output, no change)
	estimatedFee := EstimateFeeForTypes(0, 1, feeRate, "", "")

	for _, utxo := range sorted {
		selected = append(selected, utxo)
		totalInput += utxo.Value

		// Recalculate fee with current number of inputs using actual address types
		// Assume 2 outputs (payment + change) - use input type for change output
		inputType := utxo.AddressType
		if inputType == "" {
			inputType = AddressTypeP2WPKH
		}
		estimatedFee = EstimateFeeForUTXOs(selected, 2, feeRate, inputType)

		if totalInput >= targetAmount+estimatedFee {
			return selected, estimatedFee, nil
		}
	}

	return nil, 0, fmt.Errorf("insufficient funds: have %d, need %d + %d fee",
		totalInput, targetAmount, estimatedFee)
}

// estimateFee calculates the estimated fee for a transaction (legacy, assumes P2WPKH)
func estimateFee(numInputs, numOutputs int, feeRate int64) int64 {
	// Use int64 throughout to prevent overflow with extreme inputs
	vsize := int64(TxOverhead) + (int64(numInputs) * int64(P2WPKHInputSize)) + (int64(numOutputs) * int64(P2WPKHOutputSize))
	return vsize * feeRate
}

// EstimateFeeForTypes calculates fee with proper input/output sizes based on address types
func EstimateFeeForTypes(numInputs, numOutputs int, feeRate int64, inputType, outputType string) int64 {
	inputSize := int64(P2WPKHInputSize)
	if inputType == AddressTypeP2TR {
		inputSize = int64(P2TRInputSize)
	}

	outputSize := int64(P2WPKHOutputSize)
	if outputType == AddressTypeP2TR {
		outputSize = int64(P2TROutputSize)
	}

	// Use int64 throughout to prevent overflow with extreme inputs
	vsize := int64(TxOverhead) + (int64(numInputs) * inputSize) + (int64(numOutputs) * outputSize)
	return vsize * feeRate
}

// EstimateFeeForUTXOs calculates fee based on actual UTXO address types
func EstimateFeeForUTXOs(utxos []UTXO, numOutputs int, feeRate int64, outputType string) int64 {
	// Use int64 throughout to prevent overflow with extreme inputs
	var inputVSize int64
	for _, utxo := range utxos {
		if utxo.AddressType == AddressTypeP2TR {
			inputVSize += int64(P2TRInputSize)
		} else {
			inputVSize += int64(P2WPKHInputSize)
		}
	}

	outputSize := int64(P2WPKHOutputSize)
	if outputType == AddressTypeP2TR {
		outputSize = int64(P2TROutputSize)
	}

	vsize := int64(TxOverhead) + inputVSize + (int64(numOutputs) * outputSize)
	return vsize * feeRate
}

// BuildTransaction creates a signed Bitcoin transaction
func BuildTransaction(
	seed []byte,
	network string,
	utxos []UTXO,
	outputs []TxOutput,
	changeAddress string,
	feeRate int64,
) (*TransactionResult, error) {
	params, err := NetworkParams(network)
	if err != nil {
		return nil, err
	}

	// Calculate total output value
	var totalOutput int64
	for _, out := range outputs {
		if out.Value < DustLimit {
			return nil, fmt.Errorf("output value %d is below dust limit %d", out.Value, DustLimit)
		}
		totalOutput += out.Value
	}

	// Calculate total input value
	var totalInput int64
	for _, utxo := range utxos {
		totalInput += utxo.Value
	}

	// Calculate fee
	numOutputs := len(outputs)
	changeNeeded := false
	estimatedFee := estimateFee(len(utxos), numOutputs, feeRate)

	changeAmount := totalInput - totalOutput - estimatedFee
	if changeAmount > DustLimit {
		changeNeeded = true
		numOutputs++
		estimatedFee = estimateFee(len(utxos), numOutputs, feeRate)
		changeAmount = totalInput - totalOutput - estimatedFee
	} else if changeAmount < 0 {
		return nil, fmt.Errorf("insufficient funds: have %d, need %d + %d fee",
			totalInput, totalOutput, estimatedFee)
	} else {
		// Change is dust, add to fee
		changeAmount = 0
	}

	// Create transaction
	tx := wire.NewMsgTx(wire.TxVersion)

	// Add inputs with RBF-enabled sequence number (BIP125)
	for _, utxo := range utxos {
		txHash, err := chainhash.NewHashFromStr(utxo.TxID)
		if err != nil {
			return nil, fmt.Errorf("invalid txid %s: %w", utxo.TxID, err)
		}

		outpoint := wire.NewOutPoint(txHash, uint32(utxo.Vout))
		txIn := wire.NewTxIn(outpoint, nil, nil)
		txIn.Sequence = SequenceRBF // Enable Replace-By-Fee for fee bumping
		tx.AddTxIn(txIn)
	}

	// Add outputs
	for _, out := range outputs {
		addr, err := btcutil.DecodeAddress(out.Address, params)
		if err != nil {
			return nil, fmt.Errorf("invalid address %s: %w", out.Address, err)
		}

		pkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, fmt.Errorf("failed to create script for %s: %w", out.Address, err)
		}

		tx.AddTxOut(wire.NewTxOut(out.Value, pkScript))
	}

	// Add change output if needed
	if changeNeeded && changeAmount > DustLimit {
		changeAddr, err := btcutil.DecodeAddress(changeAddress, params)
		if err != nil {
			return nil, fmt.Errorf("invalid change address %s: %w", changeAddress, err)
		}

		changePkScript, err := txscript.PayToAddrScript(changeAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to create change script: %w", err)
		}

		tx.AddTxOut(wire.NewTxOut(changeAmount, changePkScript))
	}

	// Sign inputs
	prevOuts := make(map[wire.OutPoint]*wire.TxOut)
	for i, utxo := range utxos {
		prevOuts[tx.TxIn[i].PreviousOutPoint] = &wire.TxOut{
			Value:    utxo.Value,
			PkScript: utxo.ScriptPubKey,
		}
	}

	prevOutFetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(tx, prevOutFetcher)

	for i, utxo := range utxos {
		// Determine address type - default to P2WPKH for backwards compatibility
		addrType := utxo.AddressType
		if addrType == "" {
			addrType = AddressTypeP2WPKH
		}

		// Derive the key for this UTXO using the appropriate derivation path
		key, err := DeriveReceivingKeyForType(seed, network, utxo.AddressIndex, addrType)
		if err != nil {
			return nil, fmt.Errorf("failed to derive key for input %d: %w", i, err)
		}

		privKey, err := GetPrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to get private key for input %d: %w", i, err)
		}

		var witness wire.TxWitness

		if addrType == AddressTypeP2TR {
			// P2TR key-path spending: Schnorr signature
			sig, err := txscript.RawTxInTaprootSignature(
				tx,
				sigHashes,
				i,
				utxo.Value,
				utxo.ScriptPubKey,
				nil, // No tap leaf (key-path spend)
				txscript.SigHashDefault,
				privKey,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to create Schnorr signature for input %d: %w", i, err)
			}
			// P2TR key-path witness is just the signature
			witness = wire.TxWitness{sig}
		} else {
			// P2WPKH: ECDSA signature
			witness, err = txscript.WitnessSignature(
				tx,
				sigHashes,
				i,
				utxo.Value,
				utxo.ScriptPubKey,
				txscript.SigHashAll,
				privKey,
				true, // compressed
			)
			if err != nil {
				return nil, fmt.Errorf("failed to sign input %d: %w", i, err)
			}
		}

		tx.TxIn[i].Witness = witness
	}

	// Serialize transaction
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return nil, fmt.Errorf("failed to serialize transaction: %w", err)
	}

	txHex := hex.EncodeToString(buf.Bytes())

	// Calculate actual fee
	actualFee := totalInput - totalOutput
	if changeNeeded {
		actualFee -= changeAmount
	}

	return &TransactionResult{
		TxID:         tx.TxHash().String(),
		Hex:          txHex,
		Fee:          actualFee,
		TotalInput:   totalInput,
		TotalOutput:  totalOutput,
		ChangeAmount: changeAmount,
		Size:         buf.Len(),
		VSize:        tx.SerializeSizeStripped() + (tx.SerializeSize()-tx.SerializeSizeStripped()+3)/4,
	}, nil
}

// EstimateTransactionFee estimates the fee for a transaction
func EstimateTransactionFee(numInputs, numOutputs int, feeRate int64) int64 {
	return estimateFee(numInputs, numOutputs, feeRate)
}

// BuildConsolidationTransaction creates a transaction that consolidates multiple UTXOs
// into a single output. All input value (minus fee) goes to the destination address.
func BuildConsolidationTransaction(
	seed []byte,
	network string,
	utxos []UTXO,
	destinationAddress string,
	feeRate int64,
) (*TransactionResult, error) {
	if len(utxos) < 2 {
		return nil, fmt.Errorf("need at least 2 UTXOs to consolidate, got %d", len(utxos))
	}

	params, err := NetworkParams(network)
	if err != nil {
		return nil, err
	}

	// Calculate total input value
	var totalInput int64
	for _, utxo := range utxos {
		totalInput += utxo.Value
	}

	// Detect output address type for proper fee calculation
	outputType := AddressTypeP2WPKH
	if detectedType, err := GetAddressType(destinationAddress, network); err == nil && detectedType == "p2tr" {
		outputType = AddressTypeP2TR
	}

	// Calculate fee using proper address-type-aware estimation
	fee := EstimateFeeForUTXOs(utxos, 1, feeRate, outputType)

	// Calculate output value
	outputValue := totalInput - fee
	if outputValue <= 0 {
		return nil, fmt.Errorf("insufficient funds: total input %d, fee %d", totalInput, fee)
	}
	if outputValue < DustLimit {
		return nil, fmt.Errorf("output value %d is below dust limit %d", outputValue, DustLimit)
	}

	// Create transaction
	tx := wire.NewMsgTx(wire.TxVersion)

	// Add inputs with RBF-enabled sequence number (BIP125)
	for _, utxo := range utxos {
		txHash, err := chainhash.NewHashFromStr(utxo.TxID)
		if err != nil {
			return nil, fmt.Errorf("invalid txid %s: %w", utxo.TxID, err)
		}

		outpoint := wire.NewOutPoint(txHash, uint32(utxo.Vout))
		txIn := wire.NewTxIn(outpoint, nil, nil)
		txIn.Sequence = SequenceRBF // Enable Replace-By-Fee for fee bumping
		tx.AddTxIn(txIn)
	}

	// Add single output
	addr, err := btcutil.DecodeAddress(destinationAddress, params)
	if err != nil {
		return nil, fmt.Errorf("invalid destination address %s: %w", destinationAddress, err)
	}

	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to create script for %s: %w", destinationAddress, err)
	}

	tx.AddTxOut(wire.NewTxOut(outputValue, pkScript))

	// Sign inputs
	prevOuts := make(map[wire.OutPoint]*wire.TxOut)
	for i, utxo := range utxos {
		prevOuts[tx.TxIn[i].PreviousOutPoint] = &wire.TxOut{
			Value:    utxo.Value,
			PkScript: utxo.ScriptPubKey,
		}
	}

	prevOutFetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(tx, prevOutFetcher)

	for i, utxo := range utxos {
		// Determine address type - default to P2WPKH for backwards compatibility
		addrType := utxo.AddressType
		if addrType == "" {
			addrType = AddressTypeP2WPKH
		}

		// Derive the key for this UTXO using the appropriate derivation path
		key, err := DeriveReceivingKeyForType(seed, network, utxo.AddressIndex, addrType)
		if err != nil {
			return nil, fmt.Errorf("failed to derive key for input %d: %w", i, err)
		}

		privKey, err := GetPrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to get private key for input %d: %w", i, err)
		}

		var witness wire.TxWitness

		if addrType == AddressTypeP2TR {
			// P2TR key-path spending: Schnorr signature
			sig, err := txscript.RawTxInTaprootSignature(
				tx,
				sigHashes,
				i,
				utxo.Value,
				utxo.ScriptPubKey,
				nil, // No tap leaf (key-path spend)
				txscript.SigHashDefault,
				privKey,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to create Schnorr signature for input %d: %w", i, err)
			}
			// P2TR key-path witness is just the signature
			witness = wire.TxWitness{sig}
		} else {
			// P2WPKH: ECDSA signature
			witness, err = txscript.WitnessSignature(
				tx,
				sigHashes,
				i,
				utxo.Value,
				utxo.ScriptPubKey,
				txscript.SigHashAll,
				privKey,
				true, // compressed
			)
			if err != nil {
				return nil, fmt.Errorf("failed to sign input %d: %w", i, err)
			}
		}

		tx.TxIn[i].Witness = witness
	}

	// Serialize transaction
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return nil, fmt.Errorf("failed to serialize transaction: %w", err)
	}

	txHex := hex.EncodeToString(buf.Bytes())

	return &TransactionResult{
		TxID:         tx.TxHash().String(),
		Hex:          txHex,
		Fee:          fee,
		TotalInput:   totalInput,
		TotalOutput:  outputValue,
		ChangeAmount: 0, // No change in consolidation
		Size:         buf.Len(),
		VSize:        tx.SerializeSizeStripped() + (tx.SerializeSize()-tx.SerializeSizeStripped()+3)/4,
	}, nil
}
