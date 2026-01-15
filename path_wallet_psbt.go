package btc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/djschnei21/vault-plugin-btc/wallet"
)

func pathWalletPSBT(b *btcBackend) []*framework.Path {
	return []*framework.Path{
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

	// Get stored addresses to find which inputs we can sign (for single-sig)
	addresses, err := getStoredAddresses(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	// Build address to index map for single-sig lookup
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

		// Try multiple signing strategies
		signed := false

		// Strategy 1: Direct address match (single-sig P2WPKH/P2TR)
		if !signed {
			signed = b.trySignSingleSig(p, i, input, params, network, w, addrToIndex, sigHashes)
			if signed {
				signedCount++
				continue
			}
		}

		// Strategy 2: BIP32 derivation matching (multi-sig and external PSBTs)
		if !signed {
			signed = b.trySignByBip32Derivation(p, i, input, network, w, sigHashes)
			if signed {
				signedCount++
				continue
			}
		}

		// Strategy 3: Scan our keys against witness script (multi-sig P2WSH)
		if !signed && input.WitnessScript != nil {
			signed = b.trySignMultiSig(p, i, input, network, w, sigHashes)
			if signed {
				signedCount++
			}
		}
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

// trySignSingleSig attempts to sign a single-sig input by matching the address
func (b *btcBackend) trySignSingleSig(p *psbt.Packet, inputIndex int, input psbt.PInput,
	params *chaincfg.Params, network string, w *btcWallet,
	addrToIndex map[string]uint32, sigHashes *txscript.TxSigHashes) bool {

	// Extract address from scriptPubKey
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(input.WitnessUtxo.PkScript, params)
	if err != nil || len(addrs) == 0 {
		return false
	}

	addr := addrs[0].EncodeAddress()
	index, ok := addrToIndex[addr]
	if !ok {
		return false // Not our address
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
		return false
	}

	return b.signInput(p, inputIndex, input, key, addrType, sigHashes)
}

// trySignByBip32Derivation attempts to sign by matching BIP32 derivation paths in the PSBT
func (b *btcBackend) trySignByBip32Derivation(p *psbt.Packet, inputIndex int, input psbt.PInput,
	network string, w *btcWallet, sigHashes *txscript.TxSigHashes) bool {

	// Check BIP32 derivation entries
	for _, deriv := range input.Bip32Derivation {
		if deriv == nil || len(deriv.Bip32Path) < 5 {
			continue
		}

		// Parse the derivation path to extract purpose, coin, account, change, index
		// Path format: purpose'/coin'/account'/change/index
		path := deriv.Bip32Path

		// Check if this matches our wallet's derivation pattern
		addrType, index, isOurs := b.matchDerivationPath(path, network, w.AddressType)
		if !isOurs {
			continue
		}

		// Derive our key for this path
		var key *hdkeychain.ExtendedKey
		var err error

		// Determine if this is receiving (change=0) or change (change=1) address
		change := path[3]
		if change == 0 {
			key, err = wallet.DeriveReceivingKeyForType(w.Seed, network, index, addrType)
		} else {
			key, err = wallet.DeriveChangeKeyForType(w.Seed, network, index, addrType)
		}
		if err != nil {
			continue
		}

		// Verify our pubkey matches the one in the PSBT
		ourPubKey, err := wallet.GetPublicKey(key)
		if err != nil {
			continue
		}

		if !bytes.Equal(ourPubKey.SerializeCompressed(), deriv.PubKey) {
			continue // Pubkey doesn't match - not our key
		}

		b.Logger().Debug("matched BIP32 derivation", "input", inputIndex, "index", index, "type", addrType)

		// Check if this is a multi-sig (has witness script)
		if input.WitnessScript != nil {
			return b.signMultiSigInput(p, inputIndex, input, key, sigHashes)
		}

		return b.signInput(p, inputIndex, input, key, addrType, sigHashes)
	}

	return false
}

// trySignMultiSig scans our wallet's keys to find any that are in the witness script
func (b *btcBackend) trySignMultiSig(p *psbt.Packet, inputIndex int, input psbt.PInput,
	network string, w *btcWallet, sigHashes *txscript.TxSigHashes) bool {

	// Extract pubkeys from the witness script
	scriptPubKeys := extractPubKeysFromScript(input.WitnessScript)
	if len(scriptPubKeys) == 0 {
		return false
	}

	// Try to find a matching key from our wallet
	// We'll scan a reasonable range of indices (0 to NextAddressIndex + gap)
	maxIndex := w.NextAddressIndex + 20 // Include some gap limit
	if maxIndex < 100 {
		maxIndex = 100 // Minimum scan range
	}

	for idx := uint32(0); idx < maxIndex; idx++ {
		// Try both receiving and change paths
		for _, change := range []uint32{0, 1} {
			var key *hdkeychain.ExtendedKey
			var err error

			if change == 0 {
				key, err = wallet.DeriveReceivingKeyForType(w.Seed, network, idx, w.AddressType)
			} else {
				key, err = wallet.DeriveChangeKeyForType(w.Seed, network, idx, w.AddressType)
			}
			if err != nil {
				continue
			}

			pubKey, err := wallet.GetPublicKey(key)
			if err != nil {
				continue
			}

			pubKeyBytes := pubKey.SerializeCompressed()

			// Check if this pubkey is in the witness script
			for _, scriptPubKey := range scriptPubKeys {
				if bytes.Equal(pubKeyBytes, scriptPubKey) {
					b.Logger().Debug("found matching key in witness script",
						"input", inputIndex, "index", idx, "change", change)
					return b.signMultiSigInput(p, inputIndex, input, key, sigHashes)
				}
			}
		}
	}

	return false
}

// matchDerivationPath checks if a BIP32 path matches our wallet's derivation pattern
func (b *btcBackend) matchDerivationPath(path []uint32, network string, walletAddrType string) (string, uint32, bool) {
	if len(path) < 5 {
		return "", 0, false
	}

	// Expected path: purpose'/coin'/account'/change/index
	// Hardened values have 0x80000000 added
	const hardenedOffset = 0x80000000

	purpose := path[0]
	coin := path[1]
	account := path[2]
	// change := path[3] // 0 = receiving, 1 = change
	index := path[4]

	// Determine address type from purpose
	var addrType string
	switch purpose {
	case hardenedOffset + 84: // m/84'
		addrType = wallet.AddressTypeP2WPKH
	case hardenedOffset + 86: // m/86'
		addrType = wallet.AddressTypeP2TR
	default:
		return "", 0, false // Unknown purpose
	}

	// Check coin type matches network
	expectedCoin := uint32(hardenedOffset + 0) // mainnet
	if network == "testnet4" || network == "signet" {
		expectedCoin = hardenedOffset + 1 // testnet
	}
	if coin != expectedCoin {
		return "", 0, false
	}

	// We only support account 0
	if account != hardenedOffset+0 {
		return "", 0, false
	}

	return addrType, index, true
}

// signInput signs a single-sig input (P2WPKH or P2TR key-path)
func (b *btcBackend) signInput(p *psbt.Packet, inputIndex int, input psbt.PInput,
	key *hdkeychain.ExtendedKey, addrType string, sigHashes *txscript.TxSigHashes) bool {

	privKey, err := wallet.GetPrivateKey(key)
	if err != nil {
		return false
	}

	pubKey, _ := wallet.GetPublicKey(key)

	if addrType == wallet.AddressTypeP2TR {
		// P2TR: Use Schnorr signature with SigHashDefault
		sig, err := txscript.RawTxInTaprootSignature(
			p.UnsignedTx,
			sigHashes,
			inputIndex,
			input.WitnessUtxo.Value,
			input.WitnessUtxo.PkScript,
			nil, // No tap leaf (key-path spend)
			txscript.SigHashDefault,
			privKey,
		)
		if err != nil {
			return false
		}
		p.Inputs[inputIndex].TaprootKeySpendSig = sig
	} else {
		// P2WPKH: Use ECDSA signature with SigHashAll
		witness, err := txscript.WitnessSignature(
			p.UnsignedTx, sigHashes, inputIndex,
			input.WitnessUtxo.Value,
			input.WitnessUtxo.PkScript,
			txscript.SigHashAll,
			privKey, true,
		)
		if err != nil {
			return false
		}
		// Add partial signature to PSBT
		p.Inputs[inputIndex].PartialSigs = append(p.Inputs[inputIndex].PartialSigs, &psbt.PartialSig{
			PubKey:    pubKey.SerializeCompressed(),
			Signature: witness[0],
		})
	}

	return true
}

// signMultiSigInput signs a multi-sig input (P2WSH)
func (b *btcBackend) signMultiSigInput(p *psbt.Packet, inputIndex int, input psbt.PInput,
	key *hdkeychain.ExtendedKey, sigHashes *txscript.TxSigHashes) bool {

	privKey, err := wallet.GetPrivateKey(key)
	if err != nil {
		return false
	}

	pubKey, err := wallet.GetPublicKey(key)
	if err != nil {
		return false
	}

	// For P2WSH, we sign against the witness script (not the scriptPubKey)
	// The scriptPubKey is just OP_0 <32-byte-hash>
	sig, err := txscript.RawTxInWitnessSignature(
		p.UnsignedTx,
		sigHashes,
		inputIndex,
		input.WitnessUtxo.Value,
		input.WitnessScript, // Sign against the actual script
		txscript.SigHashAll,
		privKey,
	)
	if err != nil {
		b.Logger().Debug("multi-sig signing failed", "input", inputIndex, "error", err)
		return false
	}

	// Add partial signature (append to existing, don't replace)
	p.Inputs[inputIndex].PartialSigs = append(p.Inputs[inputIndex].PartialSigs, &psbt.PartialSig{
		PubKey:    pubKey.SerializeCompressed(),
		Signature: sig,
	})

	return true
}

// extractPubKeysFromScript extracts public keys from a multi-sig witness script
func extractPubKeysFromScript(script []byte) [][]byte {
	var pubKeys [][]byte

	// Parse the script looking for pubkey pushes (33 bytes for compressed keys)
	for i := 0; i < len(script); {
		opcode := script[i]
		i++

		// Check for compressed pubkey push (33 bytes)
		if opcode == 0x21 && i+33 <= len(script) {
			pubKey := script[i : i+33]
			// Verify it looks like a compressed pubkey (starts with 0x02 or 0x03)
			if pubKey[0] == 0x02 || pubKey[0] == 0x03 {
				pubKeys = append(pubKeys, pubKey)
			}
			i += 33
		} else if opcode >= 0x01 && opcode <= 0x4b {
			// Other data push - skip it
			i += int(opcode)
		}
		// Skip other opcodes (OP_N, OP_CHECKMULTISIG, etc.)
	}

	return pubKeys
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

const pathPSBTSignHelpSynopsis = `
Sign a PSBT with wallet keys (supports single-sig and multi-sig).
`

const pathPSBTSignHelpDescription = `
This endpoint signs a PSBT with keys from this wallet. It supports both
single-sig and multi-sig (P2WSH) inputs, making it suitable for:

  - Single-sig wallets managed entirely by Vault
  - Multi-sig setups where Vault holds one of the signing keys

Signing Strategies (tried in order):
  1. Direct address match - for single-sig P2WPKH/P2TR inputs
  2. BIP32 derivation matching - uses derivation paths in PSBT to find our key
  3. Witness script scanning - for multi-sig, scans the script for our pubkeys

Multi-sig Workflow:
  1. Export xpub from Vault: vault read btc/wallets/my-wallet/xpub
  2. Create multi-sig wallet in Sparrow/Caravan with Vault's xpub + other signers
  3. When spending, create PSBT in the coordinator
  4. Sign with Vault: vault write btc/wallets/my-wallet/psbt/sign psbt="..."
  5. Collect signatures from other signers
  6. Finalize and broadcast

Example (single-sig):
  $ vault write btc/wallets/my-wallet/psbt/sign psbt="cHNidP8BAH..."

Example (multi-sig - Vault is one signer):
  $ vault write btc/wallets/my-wallet/psbt/sign psbt="cHNidP8BAH..."
  # Returns PSBT with Vault's signature added
  # Send to other signers, then finalize when threshold met

Parameters:
  - psbt: Base64-encoded PSBT to sign (required)

Response:
  - psbt: Signed PSBT (base64)
  - inputs_total: Total number of inputs in the PSBT
  - inputs_signed: Number of inputs this wallet signed

Only inputs where this wallet can provide a signature are signed. Other inputs
are left unchanged, allowing the PSBT to be passed to additional signers.
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
