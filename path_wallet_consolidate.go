package btc

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/djschnei21/vault-plugin-btc/wallet"
)

func pathWalletConsolidate(b *btcBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "wallets/" + framework.GenericNameRegex("name") + "/consolidate",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "btc",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the wallet",
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
				"below_value": {
					Type:        framework.TypeInt,
					Description: "Only consolidate UTXOs with value below this threshold in satoshis (default: consolidate all)",
					Default:     0,
				},
				"dry_run": {
					Type:        framework.TypeBool,
					Description: "Preview consolidation without broadcasting (default: false)",
					Default:     false,
				},
				"compact": {
					Type:        framework.TypeBool,
					Description: "Run compaction after consolidation to clean up spent empty addresses (default: false)",
					Default:     false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathWalletConsolidate,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "consolidate",
					},
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathWalletConsolidate,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "consolidate",
					},
				},
			},
			ExistenceCheck:  b.pathWalletConsolidateExistenceCheck,
			HelpSynopsis:    pathWalletConsolidateHelpSynopsis,
			HelpDescription: pathWalletConsolidateHelpDescription,
		},
	}
}

func (b *btcBackend) pathWalletConsolidateExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	return false, nil
}

func (b *btcBackend) pathWalletConsolidate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	feeRate := int64(data.Get("fee_rate").(int))
	minConfOverride := data.Get("min_confirmations").(int)
	belowValue := int64(data.Get("below_value").(int))
	dryRun := data.Get("dry_run").(bool)
	compact := data.Get("compact").(bool)

	b.Logger().Debug("consolidate request", "wallet", name, "fee_rate", feeRate, "below_value", belowValue, "dry_run", dryRun, "compact", compact)

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

	// Determine min_confirmations
	minConfirmations := minConfOverride
	if minConfirmations < 0 {
		minConfirmations, err = getMinConfirmations(ctx, req.Storage)
		if err != nil {
			return nil, err
		}
	}

	// Get all UTXOs
	utxoInfos, err := b.getUTXOsForWallet(ctx, req.Storage, name, minConfirmations)
	if err != nil {
		return nil, fmt.Errorf("failed to get UTXOs: %w", err)
	}

	if len(utxoInfos) == 0 {
		return logical.ErrorResponse("no UTXOs available for consolidation"), nil
	}

	// Filter UTXOs if below_value threshold is set
	var selectedUTXOs []UTXOInfo
	var totalInput int64

	if belowValue > 0 {
		// Only consolidate UTXOs below the threshold
		for _, utxo := range utxoInfos {
			if utxo.Value < belowValue {
				selectedUTXOs = append(selectedUTXOs, utxo)
				totalInput += utxo.Value
			}
		}
		b.Logger().Debug("filtered UTXOs by value threshold", "below_value", belowValue, "selected", len(selectedUTXOs), "total", len(utxoInfos))
	} else {
		// Consolidate all UTXOs
		selectedUTXOs = utxoInfos
		for _, utxo := range utxoInfos {
			totalInput += utxo.Value
		}
	}

	// Need at least 2 UTXOs to consolidate
	if len(selectedUTXOs) < 2 {
		if belowValue > 0 {
			return logical.ErrorResponse("only %d UTXO(s) below %d satoshis - need at least 2 to consolidate", len(selectedUTXOs), belowValue), nil
		}
		return logical.ErrorResponse("only %d UTXO(s) available - need at least 2 to consolidate", len(selectedUTXOs)), nil
	}

	// Privacy warning
	b.Logger().Warn("PRIVACY: consolidation links all input addresses together via common-input-ownership heuristic",
		"wallet", name, "utxos_to_consolidate", len(selectedUTXOs))

	// Convert to wallet.UTXO for transaction building
	walletUTXOs := make([]wallet.UTXO, 0, len(selectedUTXOs))
	for _, info := range selectedUTXOs {
		scriptPubKey, err := wallet.GetScriptPubKey(info.Address, network)
		if err != nil {
			b.Logger().Warn("failed to get scriptPubKey", "address", info.Address, "error", err)
			continue
		}

		walletUTXOs = append(walletUTXOs, wallet.UTXO{
			TxID:         info.TxID,
			Vout:         info.Vout,
			Value:        info.Value,
			Address:      info.Address,
			AddressIndex: info.AddressIndex,
			ScriptPubKey: scriptPubKey,
			AddressType:  w.AddressType,
		})
	}

	// Estimate fee using address-type-aware calculation (matches BuildConsolidationTransaction)
	estimatedFee := wallet.EstimateFeeForUTXOs(walletUTXOs, 1, feeRate, w.AddressType)
	// Calculate vsize for display
	inputVSize := 0
	for _, utxo := range walletUTXOs {
		if utxo.AddressType == wallet.AddressTypeP2TR {
			inputVSize += wallet.P2TRInputSize
		} else {
			inputVSize += wallet.P2WPKHInputSize
		}
	}
	outputSize := wallet.P2WPKHOutputSize
	if w.AddressType == wallet.AddressTypeP2TR {
		outputSize = wallet.P2TROutputSize
	}
	estimatedVSize := wallet.TxOverhead + inputVSize + outputSize

	// Calculate output value
	outputValue := totalInput - estimatedFee

	if outputValue <= 0 {
		return logical.ErrorResponse("insufficient funds: total input %d satoshis, estimated fee %d satoshis", totalInput, estimatedFee), nil
	}

	if outputValue < wallet.DustLimit {
		return logical.ErrorResponse("output would be below dust limit (%d satoshis): total input %d, fee %d, output %d",
			wallet.DustLimit, totalInput, estimatedFee, outputValue), nil
	}

	// Generate destination address (fresh address for consolidation output)
	destAddr, err := wallet.GenerateAddressFromSeedForType(w.Seed, network, w.NextAddressIndex, w.AddressType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate destination address: %w", err)
	}

	// If dry run, return estimate without broadcasting
	if dryRun {
		b.Logger().Debug("consolidate dry run complete", "wallet", name, "inputs", len(walletUTXOs), "output_value", outputValue)
		return &logical.Response{
			Data: map[string]interface{}{
				"dry_run":               true,
				"inputs_to_consolidate": len(walletUTXOs),
				"total_input":           totalInput,
				"estimated_fee":         estimatedFee,
				"estimated_vsize":       estimatedVSize,
				"output_value":          outputValue,
				"output_address":        destAddr,
				"fee_rate":              feeRate,
				"privacy_warning":       "Consolidation links all input addresses together, revealing common ownership",
			},
		}, nil
	}

	// Store destination address
	addrInfo, err := wallet.GenerateAddressInfoForType(w.Seed, network, w.NextAddressIndex, w.AddressType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate address info: %w", err)
	}

	stored := &storedAddress{
		Address:        addrInfo.Address,
		Index:          addrInfo.Index,
		DerivationPath: addrInfo.DerivationPath,
		ScriptHash:     addrInfo.ScriptHash,
	}

	storageKey := fmt.Sprintf("%s%s/%d", addressStoragePrefix, name, w.NextAddressIndex)
	entry, err := logical.StorageEntryJSON(storageKey, stored)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage entry: %w", err)
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to store address: %w", err)
	}

	w.NextAddressIndex++
	if err := saveWallet(ctx, req.Storage, w); err != nil {
		return nil, fmt.Errorf("failed to update wallet: %w", err)
	}

	// Build consolidation transaction (single output to ourselves)
	outputs := []wallet.TxOutput{
		{
			Address: destAddr,
			Value:   outputValue,
		},
	}

	// Build transaction with no change (all value goes to single output)
	txResult, err := wallet.BuildConsolidationTransaction(
		w.Seed,
		network,
		walletUTXOs,
		outputs[0].Address,
		feeRate,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build consolidation transaction: %w", err)
	}

	// Broadcast
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Electrum: %w", err)
	}

	txid, err := client.BroadcastTransaction(txResult.Hex)
	if err != nil {
		b.Logger().Warn("consolidation broadcast failed", "wallet", name, "error", err)
		return &logical.Response{
			Data: map[string]interface{}{
				"error":               err.Error(),
				"txid":                txResult.TxID,
				"hex":                 txResult.Hex,
				"inputs_consolidated": len(walletUTXOs),
				"total_input":         totalInput,
				"fee":                 txResult.Fee,
				"output_value":        outputValue,
				"output_address":      destAddr,
				"broadcast":           false,
			},
		}, nil
	}

	// Invalidate cache after successful broadcast
	b.cache.InvalidateWallet(name)

	// Mark input addresses as spent (never receive to them again)
	spentIndices := make([]uint32, 0, len(walletUTXOs))
	for _, utxo := range walletUTXOs {
		spentIndices = append(spentIndices, utxo.AddressIndex)
	}
	if err := markAddressesSpent(ctx, req.Storage, name, spentIndices); err != nil {
		b.Logger().Warn("failed to mark addresses as spent", "wallet", name, "error", err)
		// Non-fatal: transaction was broadcast successfully
	}

	b.Logger().Info("consolidation broadcast successful",
		"wallet", name,
		"txid", txid,
		"inputs_consolidated", len(walletUTXOs),
		"total_input", totalInput,
		"fee", txResult.Fee,
		"output_value", outputValue)

	respData := map[string]interface{}{
		"txid":                txid,
		"inputs_consolidated": len(walletUTXOs),
		"total_input":         totalInput,
		"fee":                 txResult.Fee,
		"output_value":        outputValue,
		"output_address":      destAddr,
		"broadcast":           true,
		"privacy_warning":     "Consolidation links all input addresses together, revealing common ownership",
	}

	// Run compaction if requested
	if compact {
		compactResult, err := b.runCompaction(ctx, req.Storage, name, network, client)
		if err != nil {
			b.Logger().Warn("compaction after consolidation failed", "wallet", name, "error", err)
			respData["compact_error"] = err.Error()
		} else {
			respData["compact_addresses_deleted"] = compactResult.AddressesDeleted
			respData["compact_new_first_active"] = compactResult.NewFirstActive
			b.Logger().Info("compaction after consolidation successful",
				"wallet", name,
				"addresses_deleted", compactResult.AddressesDeleted)
		}
	}

	return &logical.Response{Data: respData}, nil
}

const pathWalletConsolidateHelpSynopsis = `
Consolidate multiple UTXOs into a single UTXO.
`

const pathWalletConsolidateHelpDescription = `
This endpoint consolidates multiple UTXOs into a single UTXO, reducing future
transaction fees and cleaning up dust. This is similar to Sparrow wallet's
UTXO consolidation feature.

PRIVACY WARNING: Consolidation links all input addresses together via the
common-input-ownership heuristic, revealing they are controlled by the same
entity. Only consolidate when privacy implications are acceptable.

Example - Consolidate all UTXOs:
  $ vault write btc/wallets/treasury/consolidate fee_rate=5

Example - Consolidate only small UTXOs (dust cleanup):
  $ vault write btc/wallets/treasury/consolidate below_value=10000 fee_rate=5

Example - Preview consolidation without broadcasting:
  $ vault write btc/wallets/treasury/consolidate dry_run=true

Example - Consolidate and compact in one operation:
  $ vault write btc/wallets/treasury/consolidate compact=true

Parameters:
  - fee_rate: Fee rate in satoshis per vbyte (default: 10)
  - min_confirmations: Minimum UTXO confirmations (default: from config)
  - below_value: Only consolidate UTXOs below this value in satoshis
                 (default: 0, meaning consolidate all UTXOs)
  - dry_run: Preview without broadcasting (default: false)
  - compact: Run compaction after consolidation to clean up spent empty
             address records (default: false)

Response:
  - txid: Transaction ID (if broadcast)
  - inputs_consolidated: Number of UTXOs consolidated
  - total_input: Total value of all inputs
  - fee: Transaction fee paid
  - output_value: Value of the consolidated UTXO
  - output_address: Address receiving the consolidated funds
  - broadcast: Whether the transaction was broadcast
  - privacy_warning: Reminder about privacy implications

Best practices:
  - Consolidate during low-fee periods to minimize costs
  - Use below_value to clean up dust UTXOs without consolidating everything
  - Consider privacy implications before consolidating
  - Use dry_run to preview before committing

All amounts are in satoshis (1 BTC = 100,000,000 satoshis).
`
