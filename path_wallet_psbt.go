package btc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/dan/vault-plugin-secrets-btc/wallet"
)

func pathWalletPSBT(b *btcBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "wallets/" + framework.GenericNameRegex("name") + "/psbt/create",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "btc",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the wallet",
					Required:    true,
				},
				"outputs": {
					Type:        framework.TypeString,
					Description: "JSON array of outputs: [{\"address\": \"bc1...\", \"amount\": 50000}, ...]",
					Required:    true,
				},
				"fee_rate": {
					Type:        framework.TypeInt,
					Description: "Fee rate in satoshis per vbyte (default: 10)",
					Default:     10,
				},
				"min_confirmations": {
					Type:        framework.TypeInt,
					Description: "Minimum confirmations for UTXOs (default: from config)",
					Default:     -1,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathWalletPSBTCreate,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "psbt-create",
					},
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathWalletPSBTCreate,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "psbt-create",
					},
				},
			},
			ExistenceCheck:  b.pathWalletPSBTExistenceCheck,
			HelpSynopsis:    pathPSBTCreateHelpSynopsis,
			HelpDescription: pathPSBTCreateHelpDescription,
		},
		{
			Pattern: "wallets/" + framework.GenericNameRegex("name") + "/psbt/sign",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "btc",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the wallet",
					Required:    true,
				},
				"psbt": {
					Type:        framework.TypeString,
					Description: "Base64-encoded PSBT to sign",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathWalletPSBTSign,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "psbt-sign",
					},
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathWalletPSBTSign,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "psbt-sign",
					},
				},
			},
			ExistenceCheck:  b.pathWalletPSBTExistenceCheck,
			HelpSynopsis:    pathPSBTSignHelpSynopsis,
			HelpDescription: pathPSBTSignHelpDescription,
		},
		{
			Pattern: "wallets/" + framework.GenericNameRegex("name") + "/psbt/finalize",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "btc",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the wallet",
					Required:    true,
				},
				"psbt": {
					Type:        framework.TypeString,
					Description: "Base64-encoded signed PSBT to finalize",
					Required:    true,
				},
				"broadcast": {
					Type:        framework.TypeBool,
					Description: "Whether to broadcast the transaction (default: true)",
					Default:     true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathWalletPSBTFinalize,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "psbt-finalize",
					},
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathWalletPSBTFinalize,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "psbt-finalize",
					},
				},
			},
			ExistenceCheck:  b.pathWalletPSBTExistenceCheck,
			HelpSynopsis:    pathPSBTFinalizeHelpSynopsis,
			HelpDescription: pathPSBTFinalizeHelpDescription,
		},
	}
}

func (b *btcBackend) pathWalletPSBTExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	return false, nil
}

// PSBTOutput represents an output for PSBT creation
type PSBTOutput struct {
	Address string `json:"address"`
	Amount  int64  `json:"amount"`
}

func (b *btcBackend) pathWalletPSBTCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	outputsJSON := data.Get("outputs").(string)
	feeRate := int64(data.Get("fee_rate").(int))
	minConfOverride := data.Get("min_confirmations").(int)

	b.Logger().Debug("PSBT create request", "wallet", name, "fee_rate", feeRate)

	if feeRate <= 0 {
		return logical.ErrorResponse("fee_rate must be positive"), nil
	}

	// Safety check for unreasonably high fee rates
	if errMsg := wallet.ValidateFeeRate(feeRate); errMsg != "" {
		return logical.ErrorResponse(errMsg), nil
	}

	w, err := getWallet(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if w == nil {
		return logical.ErrorResponse("wallet %q not found", name), nil
	}

	network, err := getNetwork(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// Parse outputs JSON
	var outputs []PSBTOutput
	if err := decodeJSON(outputsJSON, &outputs); err != nil {
		return logical.ErrorResponse("invalid outputs JSON: %s", err.Error()), nil
	}

	if len(outputs) == 0 {
		return logical.ErrorResponse("at least one output is required"), nil
	}

	// Validate outputs and calculate total
	var totalOutput int64
	for i, out := range outputs {
		if out.Amount <= 0 {
			return logical.ErrorResponse("output %d: amount must be positive", i), nil
		}
		if out.Amount < wallet.DustLimit {
			return logical.ErrorResponse("output %d: amount below dust limit", i), nil
		}
		if err := wallet.ValidateAddress(out.Address, network); err != nil {
			return logical.ErrorResponse("output %d: invalid address: %s", i, err.Error()), nil
		}
		totalOutput += out.Amount
	}

	// Get min confirmations
	minConfirmations := minConfOverride
	if minConfirmations < 0 {
		minConfirmations, err = getMinConfirmations(ctx, req.Storage)
		if err != nil {
			return nil, err
		}
	}

	// Get UTXOs
	utxoInfos, err := b.getUTXOsForWallet(ctx, req.Storage, name, minConfirmations)
	if err != nil {
		return nil, fmt.Errorf("failed to get UTXOs: %w", err)
	}

	if len(utxoInfos) == 0 {
		return logical.ErrorResponse("no UTXOs available"), nil
	}

	// Convert to wallet.UTXO and select
	utxos := make([]wallet.UTXO, 0, len(utxoInfos))
	for _, info := range utxoInfos {
		scriptPubKey, err := wallet.GetScriptPubKey(info.Address, network)
		if err != nil {
			continue
		}

		utxos = append(utxos, wallet.UTXO{
			TxID:         info.TxID,
			Vout:         info.Vout,
			Value:        info.Value,
			Address:      info.Address,
			AddressIndex: info.AddressIndex,
			ScriptPubKey: scriptPubKey,
			AddressType:  w.AddressType,
		})
	}

	selectedUTXOs, totalSelected, err := wallet.SelectUTXOs(utxos, totalOutput, feeRate)
	if err != nil {
		return logical.ErrorResponse("UTXO selection failed: %s", err.Error()), nil
	}

	// Create unsigned transaction
	tx := wire.NewMsgTx(wire.TxVersion)

	// Add inputs
	for _, utxo := range selectedUTXOs {
		hash, err := chainhash.NewHashFromStr(utxo.TxID)
		if err != nil {
			return nil, fmt.Errorf("invalid txid: %w", err)
		}
		outPoint := wire.NewOutPoint(hash, uint32(utxo.Vout))
		txIn := wire.NewTxIn(outPoint, nil, nil)
		tx.AddTxIn(txIn)
	}

	// Add outputs
	for _, out := range outputs {
		scriptPubKey, err := wallet.GetScriptPubKey(out.Address, network)
		if err != nil {
			return nil, fmt.Errorf("failed to get scriptPubKey: %w", err)
		}
		txOut := wire.NewTxOut(out.Amount, scriptPubKey)
		tx.AddTxOut(txOut)
	}

	// Calculate fee and add change if needed based on address type
	var inputSize, outputSize int
	if w.AddressType == wallet.AddressTypeP2TR {
		inputSize = wallet.P2TRInputSize
		outputSize = wallet.P2TROutputSize
	} else {
		inputSize = wallet.P2WPKHInputSize
		outputSize = wallet.P2WPKHOutputSize
	}
	estimatedVSize := wallet.TxOverhead + (len(selectedUTXOs) * inputSize) + (len(outputs) * outputSize) + outputSize // +outputSize for potential change
	estimatedFee := int64(estimatedVSize) * feeRate
	changeAmount := totalSelected - totalOutput - estimatedFee

	var changeAddress string
	if changeAmount > wallet.DustLimit {
		// Generate change address using CHANGE derivation path (internal chain)
		changeAddr, err := wallet.GenerateChangeAddressFromSeedForType(w.Seed, network, w.NextAddressIndex, w.AddressType)
		if err != nil {
			return nil, fmt.Errorf("failed to generate change address: %w", err)
		}
		changeAddress = changeAddr

		// Generate scripthash for change address
		changeScriptHash, err := wallet.AddressToScriptHash(changeAddr, network)
		if err != nil {
			return nil, fmt.Errorf("failed to compute change address scripthash: %w", err)
		}

		stored := &storedAddress{
			Address:        changeAddr,
			Index:          w.NextAddressIndex,
			DerivationPath: wallet.DerivationPathForType(network, 1, w.NextAddressIndex, w.AddressType), // chain=1 for change
			ScriptHash:     changeScriptHash,
		}

		storageKey := fmt.Sprintf("%s%s/%d", addressStoragePrefix, name, w.NextAddressIndex)
		entry, err := logical.StorageEntryJSON(storageKey, stored)
		if err != nil {
			return nil, fmt.Errorf("failed to create storage entry: %w", err)
		}

		if err := req.Storage.Put(ctx, entry); err != nil {
			return nil, fmt.Errorf("failed to store change address: %w", err)
		}

		w.NextAddressIndex++
		if err := saveWallet(ctx, req.Storage, w); err != nil {
			return nil, fmt.Errorf("failed to update wallet: %w", err)
		}

		// Add change output
		changeScript, err := wallet.GetScriptPubKey(changeAddress, network)
		if err != nil {
			return nil, fmt.Errorf("failed to get change scriptPubKey: %w", err)
		}
		tx.AddTxOut(wire.NewTxOut(changeAmount, changeScript))
	} else {
		// No change, add to fee
		changeAmount = 0
	}

	// Create PSBT
	p, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to create PSBT: %w", err)
	}

	// Add witness UTXO info to each input
	for i, utxo := range selectedUTXOs {
		p.Inputs[i].WitnessUtxo = &wire.TxOut{
			Value:    utxo.Value,
			PkScript: utxo.ScriptPubKey,
		}
		// Add BIP32 derivation info - use correct derivation path for address type
		key, err := wallet.DeriveReceivingKeyForType(w.Seed, network, utxo.AddressIndex, w.AddressType)
		if err != nil {
			continue
		}
		pubKey, err := wallet.GetPublicKey(key)
		if err != nil {
			continue
		}
		p.Inputs[i].Bip32Derivation = []*psbt.Bip32Derivation{
			{
				PubKey: pubKey.SerializeCompressed(),
			},
		}
	}

	// Serialize PSBT
	var buf bytes.Buffer
	if err := p.Serialize(&buf); err != nil {
		return nil, fmt.Errorf("failed to serialize PSBT: %w", err)
	}

	psbtBase64 := base64.StdEncoding.EncodeToString(buf.Bytes())

	respData := map[string]interface{}{
		"psbt":         psbtBase64,
		"fee":          estimatedFee,
		"inputs_count": len(selectedUTXOs),
		"total_input":  totalSelected,
		"total_output": totalOutput,
	}

	if changeAddress != "" {
		respData["change_address"] = changeAddress
		respData["change_amount"] = changeAmount
	}

	return &logical.Response{Data: respData}, nil
}

func (b *btcBackend) pathWalletPSBTSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	psbtBase64 := data.Get("psbt").(string)

	b.Logger().Debug("PSBT sign request", "wallet", name)

	w, err := getWallet(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if w == nil {
		return logical.ErrorResponse("wallet %q not found", name), nil
	}

	network, err := getNetwork(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	params, err := wallet.NetworkParams(network)
	if err != nil {
		return nil, err
	}

	// Decode PSBT
	psbtBytes, err := base64.StdEncoding.DecodeString(psbtBase64)
	if err != nil {
		return logical.ErrorResponse("invalid base64 PSBT: %s", err.Error()), nil
	}

	p, err := psbt.NewFromRawBytes(bytes.NewReader(psbtBytes), false)
	if err != nil {
		return logical.ErrorResponse("invalid PSBT: %s", err.Error()), nil
	}

	// Get stored addresses to find which inputs we can sign
	addresses, err := getStoredAddresses(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	// Build address to index map
	addrToIndex := make(map[string]uint32)
	for _, addr := range addresses {
		addrToIndex[addr.Address] = addr.Index
	}

	// Sign each input we have keys for
	var signedCount int

	// Build prevOuts map for proper sighash calculation
	prevOuts := make(map[wire.OutPoint]*wire.TxOut)
	for i, input := range p.Inputs {
		if input.WitnessUtxo != nil {
			prevOuts[p.UnsignedTx.TxIn[i].PreviousOutPoint] = input.WitnessUtxo
		}
	}
	prevOutFetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(p.UnsignedTx, prevOutFetcher)

	for i, input := range p.Inputs {
		if input.WitnessUtxo == nil {
			continue
		}

		// Extract address from scriptPubKey
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(input.WitnessUtxo.PkScript, params)
		if err != nil || len(addrs) == 0 {
			continue
		}

		addr := addrs[0].EncodeAddress()
		index, ok := addrToIndex[addr]
		if !ok {
			continue // Not our address
		}

		// Detect address type from scriptPubKey
		addrType := wallet.AddressTypeP2WPKH
		detectedType, err := wallet.GetAddressType(addr, network)
		if err == nil && detectedType == "p2tr" {
			addrType = wallet.AddressTypeP2TR
		}

		// Derive the key using correct path for address type
		key, err := wallet.DeriveReceivingKeyForType(w.Seed, network, index, addrType)
		if err != nil {
			continue
		}

		privKey, err := wallet.GetPrivateKey(key)
		if err != nil {
			continue
		}

		pubKey, _ := wallet.GetPublicKey(key)

		if addrType == wallet.AddressTypeP2TR {
			// P2TR: Use Schnorr signature with SigHashDefault
			sig, err := txscript.RawTxInTaprootSignature(
				p.UnsignedTx,
				sigHashes,
				i,
				input.WitnessUtxo.Value,
				input.WitnessUtxo.PkScript,
				nil, // No tap leaf (key-path spend)
				txscript.SigHashDefault,
				privKey,
			)
			if err != nil {
				continue
			}
			// For P2TR, store in TaprootKeySpendSig field
			p.Inputs[i].TaprootKeySpendSig = sig
		} else {
			// P2WPKH: Use ECDSA signature with SigHashAll
			witness, err := txscript.WitnessSignature(
				p.UnsignedTx, sigHashes, i,
				input.WitnessUtxo.Value,
				input.WitnessUtxo.PkScript,
				txscript.SigHashAll,
				privKey, true,
			)
			if err != nil {
				continue
			}
			// Add partial signature to PSBT
			p.Inputs[i].PartialSigs = []*psbt.PartialSig{
				{
					PubKey:    pubKey.SerializeCompressed(),
					Signature: witness[0],
				},
			}
		}
		signedCount++
	}

	// Serialize signed PSBT
	var buf bytes.Buffer
	if err := p.Serialize(&buf); err != nil {
		return nil, fmt.Errorf("failed to serialize PSBT: %w", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"psbt":          base64.StdEncoding.EncodeToString(buf.Bytes()),
			"inputs_total":  len(p.Inputs),
			"inputs_signed": signedCount,
		},
	}, nil
}

func (b *btcBackend) pathWalletPSBTFinalize(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	psbtBase64 := data.Get("psbt").(string)
	broadcast := data.Get("broadcast").(bool)

	b.Logger().Debug("PSBT finalize request", "wallet", name, "broadcast", broadcast)

	w, err := getWallet(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if w == nil {
		return logical.ErrorResponse("wallet %q not found", name), nil
	}

	// Decode PSBT
	psbtBytes, err := base64.StdEncoding.DecodeString(psbtBase64)
	if err != nil {
		return logical.ErrorResponse("invalid base64 PSBT: %s", err.Error()), nil
	}

	p, err := psbt.NewFromRawBytes(bytes.NewReader(psbtBytes), false)
	if err != nil {
		return logical.ErrorResponse("invalid PSBT: %s", err.Error()), nil
	}

	// Finalize all inputs
	for i := range p.Inputs {
		if err := psbt.Finalize(p, i); err != nil {
			return logical.ErrorResponse("failed to finalize input %d: %s", i, err.Error()), nil
		}
	}

	// Extract final transaction
	finalTx, err := psbt.Extract(p)
	if err != nil {
		return logical.ErrorResponse("failed to extract transaction: %s", err.Error()), nil
	}

	// Serialize transaction
	var txBuf bytes.Buffer
	if err := finalTx.Serialize(&txBuf); err != nil {
		return nil, fmt.Errorf("failed to serialize transaction: %w", err)
	}

	txHex := hex.EncodeToString(txBuf.Bytes())
	txid := finalTx.TxHash().String()

	respData := map[string]interface{}{
		"txid": txid,
		"hex":  txHex,
	}

	if broadcast {
		client, err := b.getClient(ctx, req.Storage)
		if err != nil {
			b.Logger().Warn("PSBT finalize: failed to connect for broadcast", "wallet", name, "error", err)
			respData["broadcast"] = false
			respData["error"] = fmt.Sprintf("failed to connect: %s", err.Error())
			return &logical.Response{Data: respData}, nil
		}

		broadcastTxid, err := client.BroadcastTransaction(txHex)
		if err != nil {
			b.Logger().Warn("PSBT finalize: broadcast failed", "wallet", name, "txid", txid, "error", err)
			respData["broadcast"] = false
			respData["error"] = err.Error()
			return &logical.Response{Data: respData}, nil
		}

		// Invalidate cache after successful broadcast - UTXOs have changed
		b.cache.InvalidateWallet(name)

		b.Logger().Info("PSBT finalize: transaction broadcast", "wallet", name, "txid", broadcastTxid)
		respData["broadcast"] = true
		respData["broadcast_txid"] = broadcastTxid
	} else {
		b.Logger().Debug("PSBT finalized without broadcast", "wallet", name, "txid", txid)
		respData["broadcast"] = false
	}

	return &logical.Response{Data: respData}, nil
}

// decodeJSON is a helper to decode JSON strings
func decodeJSON(s string, v interface{}) error {
	return json.Unmarshal([]byte(s), v)
}

const pathPSBTCreateHelpSynopsis = `
Create an unsigned PSBT for complex transactions.
`

const pathPSBTCreateHelpDescription = `
This endpoint creates an unsigned Partially Signed Bitcoin Transaction (PSBT)
for complex transaction scenarios.

Example:
  $ vault write btc/wallets/my-wallet/psbt/create \
      outputs='[{"address":"bc1q...","amount":50000},{"address":"bc1q...","amount":30000}]' \
      fee_rate=10

Parameters:
  - outputs: JSON array of outputs with address and amount (required)
  - fee_rate: Fee rate in satoshis per vbyte (default: 10)
  - min_confirmations: Minimum UTXO confirmations (default: from config)

Returns a base64-encoded PSBT ready for signing.
`

const pathPSBTSignHelpSynopsis = `
Sign a PSBT with wallet keys.
`

const pathPSBTSignHelpDescription = `
This endpoint signs a PSBT with keys from this wallet.

Example:
  $ vault write btc/wallets/my-wallet/psbt/sign \
      psbt="cHNidP8BAH..."

Parameters:
  - psbt: Base64-encoded PSBT to sign (required)

Returns the signed PSBT. Only inputs belonging to this wallet are signed.
`

const pathPSBTFinalizeHelpSynopsis = `
Finalize a PSBT and optionally broadcast.
`

const pathPSBTFinalizeHelpDescription = `
This endpoint finalizes a signed PSBT and optionally broadcasts it.

Example:
  $ vault write btc/wallets/my-wallet/psbt/finalize \
      psbt="cHNidP8BAH..." \
      broadcast=true

Parameters:
  - psbt: Base64-encoded signed PSBT (required)
  - broadcast: Whether to broadcast the transaction (default: true)

Returns the final transaction hex and txid. If broadcast=true, also broadcasts
the transaction to the network.
`
