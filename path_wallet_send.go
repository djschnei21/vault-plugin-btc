package btc

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/djschnei21/vault-plugin-btc/wallet"
)

func pathWalletSend(b *btcBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "wallets/" + framework.GenericNameRegex("name") + "/send",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "btc",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the wallet",
					Required:    true,
				},
				"to": {
					Type:        framework.TypeString,
					Description: "Destination Bitcoin address",
					Required:    true,
				},
				"amount": {
					Type:        framework.TypeInt,
					Description: "Amount to send in satoshis (ignored if max_send=true)",
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
				"dry_run": {
					Type:        framework.TypeBool,
					Description: "Estimate fee without broadcasting (default: false)",
					Default:     false,
				},
				"max_send": {
					Type:        framework.TypeBool,
					Description: "Send all available funds minus fee (default: false)",
					Default:     false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathWalletSend,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "send",
					},
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathWalletSend,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "send",
					},
				},
			},
			ExistenceCheck:  b.pathWalletSendExistenceCheck,
			HelpSynopsis:    pathWalletSendHelpSynopsis,
			HelpDescription: pathWalletSendHelpDescription,
		},
	}
}

func (b *btcBackend) pathWalletSendExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	return false, nil
}

func (b *btcBackend) pathWalletSend(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	toAddress := data.Get("to").(string)
	amount := int64(data.Get("amount").(int))
	feeRate := int64(data.Get("fee_rate").(int))
	minConfOverride := data.Get("min_confirmations").(int)
	dryRun := data.Get("dry_run").(bool)
	maxSend := data.Get("max_send").(bool)

	b.Logger().Debug("send request", "wallet", name, "to", toAddress, "amount", amount, "fee_rate", feeRate, "dry_run", dryRun, "max_send", maxSend)

	// Validate inputs
	if !maxSend {
		if amount <= 0 {
			return logical.ErrorResponse("amount must be positive (or use max_send=true)"), nil
		}
		if amount < wallet.DustLimit {
			return logical.ErrorResponse("amount %d is below dust limit %d", amount, wallet.DustLimit), nil
		}
	}

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

	// Validate destination address
	if err := wallet.ValidateAddress(toAddress, network); err != nil {
		return logical.ErrorResponse("invalid destination address: %s", err.Error()), nil
	}

	// Get UTXOs
	utxoInfos, err := b.getUTXOsForWallet(ctx, req.Storage, name, minConfirmations)
	if err != nil {
		return nil, fmt.Errorf("failed to get UTXOs: %w", err)
	}

	if len(utxoInfos) == 0 {
		return logical.ErrorResponse("no UTXOs available for spending"), nil
	}

	// Convert to wallet.UTXO and calculate total available
	utxos := make([]wallet.UTXO, 0, len(utxoInfos))
	var totalAvailable int64
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
		totalAvailable += info.Value
	}

	// Handle max_send: use all UTXOs, single output (no change)
	var selectedUTXOs []wallet.UTXO
	var changeAddr string
	var changeAmount int64

	if maxSend {
		// Use all available UTXOs
		selectedUTXOs = utxos

		// Calculate fee for single output (no change)
		estimatedFee := wallet.EstimateFeeForUTXOs(selectedUTXOs, 1, feeRate, w.AddressType)
		amount = totalAvailable - estimatedFee

		if amount <= 0 {
			return logical.ErrorResponse("insufficient funds: total %d sats, estimated fee %d sats", totalAvailable, estimatedFee), nil
		}
		if amount < wallet.DustLimit {
			return logical.ErrorResponse("max send amount %d is below dust limit %d after fee", amount, wallet.DustLimit), nil
		}

		// No change output for max_send
		changeAmount = 0
	} else {
		// Normal send: select UTXOs for the amount
		var err error
		selectedUTXOs, _, err = wallet.SelectUTXOs(utxos, amount, feeRate)
		if err != nil {
			return logical.ErrorResponse("UTXO selection failed: %s", err.Error()), nil
		}

		// Generate change address
		changeAddr, err = wallet.GenerateChangeAddressFromSeedForType(w.Seed, network, w.NextAddressIndex, w.AddressType)
		if err != nil {
			return nil, fmt.Errorf("failed to generate change address: %w", err)
		}
	}

	// Detect destination address type
	destOutputSize := wallet.P2WPKHOutputSize
	if detectedType, err := wallet.GetAddressType(toAddress, network); err == nil && detectedType == "p2tr" {
		destOutputSize = wallet.P2TROutputSize
	}

	// Calculate input vsize
	inputVSize := 0
	for _, utxo := range selectedUTXOs {
		if utxo.AddressType == wallet.AddressTypeP2TR {
			inputVSize += wallet.P2TRInputSize
		} else {
			inputVSize += wallet.P2WPKHInputSize
		}
	}

	// Calculate total vsize
	outputVSize := destOutputSize
	if !maxSend {
		changeOutputSize := wallet.P2WPKHOutputSize
		if w.AddressType == wallet.AddressTypeP2TR {
			changeOutputSize = wallet.P2TROutputSize
		}
		outputVSize += changeOutputSize
	}
	estimatedVSize := wallet.TxOverhead + inputVSize + outputVSize
	estimatedFee := int64(estimatedVSize) * feeRate

	// For dry_run, return estimate without modifying state
	if dryRun {
		if !maxSend {
			// Calculate change for non-max_send
			var totalSelected int64
			for _, utxo := range selectedUTXOs {
				totalSelected += utxo.Value
			}
			changeAmount = totalSelected - amount - estimatedFee
		}

		b.Logger().Debug("send dry run", "wallet", name, "amount", amount, "fee", estimatedFee)
		return &logical.Response{
			Data: map[string]interface{}{
				"dry_run":         true,
				"amount":          amount,
				"to":              toAddress,
				"fee_rate":        feeRate,
				"estimated_fee":   estimatedFee,
				"estimated_vsize": estimatedVSize,
				"change_amount":   changeAmount,
				"inputs_used":     len(selectedUTXOs),
				"total_available": totalAvailable,
				"max_send":        maxSend,
			},
		}, nil
	}

	// Not a dry run - proceed with transaction

	// For non-max_send, store change address
	if !maxSend {
		changeKey, err := wallet.DeriveChangeKeyForType(w.Seed, network, w.NextAddressIndex, w.AddressType)
		if err != nil {
			return nil, fmt.Errorf("failed to derive change key: %w", err)
		}
		changeScriptHash, err := wallet.AddressToScriptHash(changeAddr, network)
		if err != nil {
			return nil, fmt.Errorf("failed to compute change address scripthash: %w", err)
		}
		_ = changeKey

		stored := &storedAddress{
			Address:        changeAddr,
			Index:          w.NextAddressIndex,
			DerivationPath: wallet.DerivationPathForType(network, 1, w.NextAddressIndex, w.AddressType),
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
	}

	// Build transaction
	var txResult *wallet.TransactionResult
	if maxSend {
		// Use consolidation builder for max_send (single output, no change)
		txResult, err = wallet.BuildConsolidationTransaction(
			w.Seed,
			network,
			selectedUTXOs,
			toAddress,
			feeRate,
		)
	} else {
		outputs := []wallet.TxOutput{
			{
				Address: toAddress,
				Value:   amount,
			},
		}
		txResult, err = wallet.BuildTransaction(
			w.Seed,
			network,
			selectedUTXOs,
			outputs,
			changeAddr,
			feeRate,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to build transaction: %w", err)
	}

	// Broadcast
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Electrum: %w", err)
	}

	txid, err := client.BroadcastTransaction(txResult.Hex)
	if err != nil {
		b.Logger().Warn("broadcast failed", "wallet", name, "error", err, "txid", txResult.TxID)
		respData := map[string]interface{}{
			"error":     err.Error(),
			"txid":      txResult.TxID,
			"hex":       txResult.Hex,
			"fee":       txResult.Fee,
			"amount":    amount,
			"to":        toAddress,
			"broadcast": false,
		}
		if !maxSend {
			respData["change_amount"] = txResult.ChangeAmount
			respData["change_address"] = changeAddr
		}
		return &logical.Response{Data: respData}, nil
	}

	// Invalidate cache after successful broadcast
	b.cache.InvalidateWallet(name)

	// Mark input addresses as spent
	spentIndices := make([]uint32, 0, len(selectedUTXOs))
	for _, utxo := range selectedUTXOs {
		spentIndices = append(spentIndices, utxo.AddressIndex)
	}
	if err := markAddressesSpent(ctx, req.Storage, name, spentIndices); err != nil {
		b.Logger().Warn("failed to mark addresses as spent", "wallet", name, "error", err)
	}

	b.Logger().Info("transaction broadcast", "wallet", name, "txid", txid, "amount", amount, "to", toAddress, "fee", txResult.Fee, "max_send", maxSend)

	respData := map[string]interface{}{
		"txid":      txid,
		"fee":       txResult.Fee,
		"amount":    amount,
		"to":        toAddress,
		"broadcast": true,
	}
	if !maxSend {
		respData["change_amount"] = txResult.ChangeAmount
		respData["change_address"] = changeAddr
	}
	return &logical.Response{Data: respData}, nil
}


// getUTXOsForWallet returns UTXOs for a wallet filtered by minimum confirmations
func (b *btcBackend) getUTXOsForWallet(ctx context.Context, s logical.Storage, walletName string, minConfirmations int) ([]UTXOInfo, error) {
	b.Logger().Debug("fetching UTXOs", "wallet", walletName, "min_confirmations", minConfirmations)

	w, err := getWallet(ctx, s, walletName)
	if err != nil {
		return nil, err
	}

	if w == nil {
		return nil, fmt.Errorf("wallet %q not found", walletName)
	}

	client, err := b.getClient(ctx, s)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Electrum server: %w", err)
	}

	addresses, err := getStoredAddresses(ctx, s, walletName)
	if err != nil {
		return nil, err
	}

	walletCache := b.cache.GetWalletCache(walletName)
	var allUTXOs []UTXOInfo

	// Track if we need to reconnect (stale connection detected)
	reconnectAttempted := false

	// Get current block height for confirmation calculation
	var currentBlockHeight int64
	cachedHeight := walletCache.GetBlockHeight()
	if cachedHeight > 0 {
		currentBlockHeight = cachedHeight
	} else {
		currentBlockHeight, err = client.GetBlockHeight()
		if err != nil {
			b.Logger().Warn("failed to get block height", "error", err)
			// Try reconnect
			if b.handleClientError(err) {
				reconnectAttempted = true
				if newClient, reconErr := b.getClient(ctx, s); reconErr == nil {
					client = newClient
					currentBlockHeight, _ = client.GetBlockHeight()
				}
			}
		}
		if currentBlockHeight > 0 {
			walletCache.SetBlockHeight(currentBlockHeight)
		}
	}

	for _, addr := range addresses {
		var utxos []CachedUTXO

		// Get current status hash from Electrum (lightweight call)
		currentStatus, err := client.Subscribe(addr.ScriptHash)
		if err != nil {
			b.Logger().Warn("failed to get status", "address", addr.Address, "error", err)

			// Check for connection errors and try to reconnect once
			if !reconnectAttempted && b.handleClientError(err) {
				reconnectAttempted = true
				newClient, reconErr := b.getClient(ctx, s)
				if reconErr == nil {
					client = newClient
					// Retry with fresh connection
					currentStatus, err = client.Subscribe(addr.ScriptHash)
					if err != nil {
						b.Logger().Warn("failed to get status after reconnect", "address", addr.Address, "error", err)
					}
				}
			}
		}

		// Only use cache if Subscribe succeeded
		var cached *AddressCache
		if err == nil {
			cached = walletCache.GetAddressCacheIfValid(addr.Address, currentStatus)
		}

		if cached != nil {
			b.Logger().Debug("cache hit (status match)", "address", addr.Address)
			utxos = cached.UTXOs
		} else {
			// Cache miss or stale - fetch from Electrum
			b.Logger().Debug("cache miss, fetching from Electrum", "address", addr.Address)

			// Get balance for cache
			var balance BalanceInfo
			balanceResp, balErr := client.GetBalance(addr.ScriptHash)
			if balErr != nil {
				// Try reconnect if needed
				if !reconnectAttempted && b.handleClientError(balErr) {
					reconnectAttempted = true
					if newClient, reconErr := b.getClient(ctx, s); reconErr == nil {
						client = newClient
						balanceResp, balErr = client.GetBalance(addr.ScriptHash)
					}
				}
			}
			if balErr == nil {
				balance = BalanceInfo{Confirmed: balanceResp.Confirmed, Unconfirmed: balanceResp.Unconfirmed}
			}

			// Get history for cache
			var history []TxHistoryItem
			historyResp, histErr := client.GetHistory(addr.ScriptHash)
			if histErr == nil {
				history = make([]TxHistoryItem, len(historyResp))
				for i, h := range historyResp {
					history[i] = TxHistoryItem{TxHash: h.TxHash, Height: h.Height}
				}
			}

			// Get UTXOs
			utxoResp, utxoErr := client.ListUnspent(addr.ScriptHash)
			if utxoErr != nil {
				b.Logger().Warn("failed to list unspent", "address", addr.Address, "error", utxoErr)
				// Try reconnect if needed
				if !reconnectAttempted && b.handleClientError(utxoErr) {
					reconnectAttempted = true
					if newClient, reconErr := b.getClient(ctx, s); reconErr == nil {
						client = newClient
						utxoResp, utxoErr = client.ListUnspent(addr.ScriptHash)
					}
				}
				if utxoErr != nil {
					continue
				}
			}

			utxos = make([]CachedUTXO, len(utxoResp))
			for i, u := range utxoResp {
				utxos[i] = CachedUTXO{TxID: u.TxHash, Vout: uint32(u.TxPos), Value: u.Value, Height: u.Height}
			}

			// Update cache only if Subscribe succeeded
			if currentStatus != nil {
				walletCache.SetAddressCache(addr.Address, currentStatus, balance, history, utxos)
			}
		}

		for _, utxo := range utxos {
			// Calculate actual confirmations from block height
			var confirmations int64 = 0
			if utxo.Height > 0 {
				if currentBlockHeight > 0 {
					confirmations = currentBlockHeight - utxo.Height + 1
					if confirmations < 0 {
						confirmations = 0 // Sanity check for reorgs
					}
				} else {
					// Block height unknown but UTXO is in a block - treat as 1 confirmation minimum
					confirmations = 1
				}
			}
			// Height == 0 means unconfirmed (mempool)

			if int(confirmations) < minConfirmations {
				continue
			}

			utxoInfo := UTXOInfo{
				TxID:          utxo.TxID,
				Vout:          int(utxo.Vout),
				Value:         utxo.Value,
				Address:       addr.Address,
				AddressIndex:  addr.Index,
				ScriptHash:    addr.ScriptHash,
				Height:        utxo.Height,
				Confirmations: confirmations,
			}

			allUTXOs = append(allUTXOs, utxoInfo)
		}
	}

	b.Logger().Debug("UTXOs fetched", "wallet", walletName, "utxo_count", len(allUTXOs))
	return allUTXOs, nil
}

const pathWalletSendHelpSynopsis = `
Send Bitcoin from a wallet.
`

const pathWalletSendHelpDescription = `
This endpoint creates, signs, and broadcasts a Bitcoin transaction.

Examples:
  # Send a specific amount
  $ vault write btc/wallets/my-wallet/send \
      to="bc1q..." \
      amount=50000 \
      fee_rate=10

  # Estimate fee without broadcasting (dry run)
  $ vault write btc/wallets/my-wallet/send \
      to="bc1q..." \
      amount=50000 \
      dry_run=true

  # Send all funds (empty wallet)
  $ vault write btc/wallets/my-wallet/send \
      to="bc1q..." \
      max_send=true \
      fee_rate=5

  # Preview max send amount
  $ vault write btc/wallets/my-wallet/send \
      to="bc1q..." \
      max_send=true \
      dry_run=true

Parameters:
  - to: Destination Bitcoin address (required)
  - amount: Amount in satoshis (required unless max_send=true)
  - fee_rate: Fee rate in satoshis per vbyte (default: 10)
  - min_confirmations: Minimum UTXO confirmations (default: from config)
  - dry_run: Estimate fee without broadcasting (default: false)
  - max_send: Send all available funds minus fee (default: false)

When max_send=true, the amount parameter is ignored and all UTXOs are spent
to a single output. No change address is created.

When dry_run=true, the response includes estimated_fee, estimated_vsize,
and other details without modifying wallet state or broadcasting.

All amounts are in satoshis (1 BTC = 100,000,000 satoshis).
`
