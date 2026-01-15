package btc

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/djschnei21/vault-plugin-btc/wallet"
)

func pathWalletScan(b *btcBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "wallets/" + framework.GenericNameRegex("name") + "/scan",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "btc",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the wallet",
					Required:    true,
				},
				"retired": {
					Type:        framework.TypeBool,
					Description: "Scan retired addresses below FirstActiveIndex (default: true)",
					Default:     true,
				},
				"gap": {
					Type:        framework.TypeInt,
					Description: "Scan N addresses beyond NextAddressIndex for untracked deposits (default: 0)",
					Default:     0,
				},
				"sweep": {
					Type:        framework.TypeBool,
					Description: "Sweep found retired funds to a fresh address (default: false)",
					Default:     false,
				},
				"fee_rate": {
					Type:        framework.TypeInt,
					Description: "Fee rate in satoshis per vbyte for sweep transaction (default: 10)",
					Default:     10,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathWalletScan,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "scan",
					},
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathWalletScan,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "scan",
					},
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathWalletScan,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "scan",
					},
				},
			},
			ExistenceCheck:  b.pathWalletScanExistenceCheck,
			HelpSynopsis:    pathWalletScanHelpSynopsis,
			HelpDescription: pathWalletScanHelpDescription,
		},
	}
}

func (b *btcBackend) pathWalletScanExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	return false, nil
}

func (b *btcBackend) pathWalletScan(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	scanRetired := data.Get("retired").(bool)
	gapDepth := data.Get("gap").(int)
	sweep := data.Get("sweep").(bool)
	feeRate := int64(data.Get("fee_rate").(int))

	b.Logger().Debug("scanning wallet", "wallet", name, "retired", scanRetired, "gap", gapDepth, "sweep", sweep)

	// Validate fee rate if sweep is enabled
	if sweep {
		if feeRate <= 0 {
			return logical.ErrorResponse("fee_rate must be positive when sweep=true"), nil
		}
		// Safety check for unreasonably high fee rates
		if errMsg := wallet.ValidateFeeRate(feeRate); errMsg != "" {
			return logical.ErrorResponse(errMsg), nil
		}
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

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Electrum server: %w", err)
	}

	respData := map[string]interface{}{}

	// Track if we need to reconnect (stale connection detected)
	reconnectAttempted := false

	// ========== RETIRED ADDRESS SCAN ==========
	var retiredFound []map[string]interface{}
	var retiredTotal int64
	var utxosForSweep []wallet.UTXO

	if scanRetired && w.FirstActiveIndex > 0 {
		b.Logger().Debug("scanning retired addresses", "count", w.FirstActiveIndex)

		for idx := uint32(0); idx < w.FirstActiveIndex; idx++ {
			addrInfo, err := wallet.GenerateAddressInfoForType(w.Seed, network, idx, w.AddressType)
			if err != nil {
				b.Logger().Warn("failed to regenerate address", "index", idx, "error", err)
				continue
			}

			balanceResp, err := client.GetBalance(addrInfo.ScriptHash)
			if err != nil {
				b.Logger().Warn("failed to get balance", "address", addrInfo.Address, "error", err)
				// Try reconnect if needed
				if !reconnectAttempted && b.handleClientError(err) {
					reconnectAttempted = true
					if newClient, reconErr := b.getClient(ctx, req.Storage); reconErr == nil {
						client = newClient
						balanceResp, err = client.GetBalance(addrInfo.ScriptHash)
					}
				}
				if err != nil {
					continue
				}
			}

			total := balanceResp.Confirmed + balanceResp.Unconfirmed
			if total > 0 {
				b.Logger().Warn("found funds on retired address",
					"address", addrInfo.Address, "index", idx,
					"confirmed", balanceResp.Confirmed, "unconfirmed", balanceResp.Unconfirmed)

				retiredFound = append(retiredFound, map[string]interface{}{
					"address":     addrInfo.Address,
					"index":       idx,
					"confirmed":   balanceResp.Confirmed,
					"unconfirmed": balanceResp.Unconfirmed,
					"total":       total,
				})
				retiredTotal += total

				if sweep {
					utxoResp, err := client.ListUnspent(addrInfo.ScriptHash)
					if err != nil {
						b.Logger().Warn("failed to list unspent", "address", addrInfo.Address, "error", err)
						continue
					}

					scriptPubKey, err := wallet.GetScriptPubKey(addrInfo.Address, network)
					if err != nil {
						b.Logger().Warn("failed to get scriptPubKey", "address", addrInfo.Address, "error", err)
						continue
					}

					for _, u := range utxoResp {
						utxosForSweep = append(utxosForSweep, wallet.UTXO{
							TxID:         u.TxHash,
							Vout:         u.TxPos,
							Value:        u.Value,
							Address:      addrInfo.Address,
							AddressIndex: idx,
							ScriptPubKey: scriptPubKey,
							AddressType:  w.AddressType,
						})
					}
				}
			}
		}

		respData["retired_scanned"] = w.FirstActiveIndex
		respData["retired_found"] = retiredFound
		respData["retired_total"] = retiredTotal
	}

	// ========== GAP SCAN (AHEAD) ==========
	var gapFound []map[string]interface{}
	var gapTotal int64
	var gapRegistered []map[string]interface{}
	var highestFoundIndex uint32

	if gapDepth > 0 {
		startIdx := w.NextAddressIndex
		endIdx := startIdx + uint32(gapDepth)
		b.Logger().Debug("scanning gap addresses", "start", startIdx, "end", endIdx)

		for idx := startIdx; idx < endIdx; idx++ {
			addrInfo, err := wallet.GenerateAddressInfoForType(w.Seed, network, idx, w.AddressType)
			if err != nil {
				b.Logger().Warn("failed to generate address", "index", idx, "error", err)
				continue
			}

			balanceResp, err := client.GetBalance(addrInfo.ScriptHash)
			if err != nil {
				b.Logger().Warn("failed to get balance", "address", addrInfo.Address, "error", err)
				// Try reconnect if needed
				if !reconnectAttempted && b.handleClientError(err) {
					reconnectAttempted = true
					if newClient, reconErr := b.getClient(ctx, req.Storage); reconErr == nil {
						client = newClient
						balanceResp, err = client.GetBalance(addrInfo.ScriptHash)
					}
				}
				if err != nil {
					continue
				}
			}

			total := balanceResp.Confirmed + balanceResp.Unconfirmed
			if total > 0 {
				b.Logger().Info("found funds on untracked address",
					"address", addrInfo.Address, "index", idx,
					"confirmed", balanceResp.Confirmed, "unconfirmed", balanceResp.Unconfirmed)

				gapFound = append(gapFound, map[string]interface{}{
					"address":     addrInfo.Address,
					"index":       idx,
					"confirmed":   balanceResp.Confirmed,
					"unconfirmed": balanceResp.Unconfirmed,
					"total":       total,
				})
				gapTotal += total

				// Track highest found index
				if idx >= highestFoundIndex {
					highestFoundIndex = idx
				}

				// Register this address
				stored := &storedAddress{
					Address:        addrInfo.Address,
					Index:          addrInfo.Index,
					DerivationPath: addrInfo.DerivationPath,
					ScriptHash:     addrInfo.ScriptHash,
				}

				storageKey := fmt.Sprintf("%s%s/%d", addressStoragePrefix, name, idx)
				entry, err := logical.StorageEntryJSON(storageKey, stored)
				if err != nil {
					b.Logger().Warn("failed to create storage entry", "index", idx, "error", err)
					continue
				}

				if err := req.Storage.Put(ctx, entry); err != nil {
					b.Logger().Warn("failed to store address", "index", idx, "error", err)
					continue
				}

				gapRegistered = append(gapRegistered, map[string]interface{}{
					"address": addrInfo.Address,
					"index":   idx,
				})
			}
		}

		// Update NextAddressIndex if we found addresses beyond current
		// Also fill in any gaps to maintain contiguous address storage
		if len(gapFound) > 0 && highestFoundIndex >= w.NextAddressIndex {
			newNextIndex := highestFoundIndex + 1
			b.Logger().Info("updating NextAddressIndex", "old", w.NextAddressIndex, "new", newNextIndex)

			// Fill in ALL addresses from old NextAddressIndex to new one (not just those with funds)
			// This maintains contiguous address storage and ensures proper address tracking
			for fillIdx := w.NextAddressIndex; fillIdx < newNextIndex; fillIdx++ {
				// Check if this address was already registered (has funds)
				alreadyRegistered := false
				for _, reg := range gapRegistered {
					if reg["index"].(uint32) == fillIdx {
						alreadyRegistered = true
						break
					}
				}
				if alreadyRegistered {
					continue
				}

				// Generate and store this address to fill the gap
				addrInfo, err := wallet.GenerateAddressInfoForType(w.Seed, network, fillIdx, w.AddressType)
				if err != nil {
					b.Logger().Warn("failed to generate gap-fill address", "index", fillIdx, "error", err)
					continue
				}

				stored := &storedAddress{
					Address:        addrInfo.Address,
					Index:          addrInfo.Index,
					DerivationPath: addrInfo.DerivationPath,
					ScriptHash:     addrInfo.ScriptHash,
				}

				storageKey := fmt.Sprintf("%s%s/%d", addressStoragePrefix, name, fillIdx)
				entry, err := logical.StorageEntryJSON(storageKey, stored)
				if err != nil {
					b.Logger().Warn("failed to create gap-fill storage entry", "index", fillIdx, "error", err)
					continue
				}

				if err := req.Storage.Put(ctx, entry); err != nil {
					b.Logger().Warn("failed to store gap-fill address", "index", fillIdx, "error", err)
					continue
				}

				b.Logger().Debug("filled gap address", "index", fillIdx, "address", addrInfo.Address)
			}

			w.NextAddressIndex = newNextIndex
			if err := saveWallet(ctx, req.Storage, w); err != nil {
				return nil, fmt.Errorf("failed to update wallet: %w", err)
			}
		}

		respData["gap_scanned"] = gapDepth
		respData["gap_found"] = gapFound
		respData["gap_total"] = gapTotal
		if len(gapRegistered) > 0 {
			respData["gap_registered"] = gapRegistered
			respData["new_next_index"] = w.NextAddressIndex
		}
	}

	// ========== SWEEP RETIRED FUNDS ==========
	if sweep && len(utxosForSweep) > 0 {
		// Pre-validate: check if sweep would result in dust output BEFORE modifying state
		// This prevents generating/storing addresses only to have the transaction fail
		var sweepTotal int64
		for _, utxo := range utxosForSweep {
			sweepTotal += utxo.Value
		}
		estimatedSweepFee := wallet.EstimateFeeForUTXOs(utxosForSweep, 1, feeRate, w.AddressType)
		sweepOutput := sweepTotal - estimatedSweepFee

		if sweepOutput <= 0 {
			return logical.ErrorResponse("sweep would result in negative output: total %d sats, estimated fee %d sats",
				sweepTotal, estimatedSweepFee), nil
		}
		if sweepOutput < wallet.DustLimit {
			return logical.ErrorResponse("sweep output %d sats would be below dust limit (%d sats) after %d sat fee",
				sweepOutput, wallet.DustLimit, estimatedSweepFee), nil
		}

		// Generate destination address
		destAddr, err := wallet.GenerateAddressFromSeedForType(w.Seed, network, w.NextAddressIndex, w.AddressType)
		if err != nil {
			return nil, fmt.Errorf("failed to generate destination address: %w", err)
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

		// Build sweep transaction
		txResult, err := wallet.BuildConsolidationTransaction(
			w.Seed,
			network,
			utxosForSweep,
			destAddr,
			feeRate,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to build sweep transaction: %w", err)
		}

		// Broadcast
		txid, err := client.BroadcastTransaction(txResult.Hex)
		if err != nil {
			b.Logger().Warn("sweep broadcast failed", "wallet", name, "error", err)
			respData["sweep_error"] = err.Error()
			respData["sweep_hex"] = txResult.Hex
			respData["sweep_broadcast"] = false
		} else {
			b.cache.InvalidateWallet(name)
			b.Logger().Info("sweep broadcast successful",
				"wallet", name, "txid", txid,
				"swept_addresses", len(retiredFound),
				"total_swept", retiredTotal,
				"fee", txResult.Fee)

			respData["sweep_txid"] = txid
			respData["sweep_fee"] = txResult.Fee
			respData["sweep_output"] = txResult.TotalOutput
			respData["sweep_address"] = destAddr
			respData["sweep_broadcast"] = true
		}
	}

	// ========== BUILD SUMMARY ==========
	totalFound := retiredTotal + gapTotal
	respData["total_found"] = totalFound

	if totalFound == 0 {
		if scanRetired && gapDepth > 0 {
			respData["message"] = "no funds found on retired or gap addresses"
		} else if scanRetired {
			respData["message"] = "no funds found on retired addresses"
		} else if gapDepth > 0 {
			respData["message"] = "no funds found in gap scan"
		}
	} else {
		var parts []string
		if retiredTotal > 0 {
			parts = append(parts, fmt.Sprintf("%d sats on %d retired", retiredTotal, len(retiredFound)))
		}
		if gapTotal > 0 {
			parts = append(parts, fmt.Sprintf("%d sats on %d untracked (now registered)", gapTotal, len(gapFound)))
		}
		respData["message"] = fmt.Sprintf("found: %s", joinParts(parts))
	}

	return &logical.Response{Data: respData}, nil
}

func joinParts(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	if len(parts) == 1 {
		return parts[0]
	}
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += ", " + parts[i]
	}
	return result
}

const pathWalletScanHelpSynopsis = `
Scan for funds on retired or untracked addresses.
`

const pathWalletScanHelpDescription = `
This endpoint scans for funds that may be outside the wallet's tracked addresses.
Two scan modes are available:

RETIRED SCAN (retired=true, default):
  Scans addresses below FirstActiveIndex that were compacted away. Funds here
  may have been sent to old addresses after compaction (refunds, mistakes, etc).
  Use sweep=true to move these funds to a fresh tracked address.

GAP SCAN (gap=N):
  Scans N addresses beyond NextAddressIndex for deposits to addresses we haven't
  generated yet. This detects funds sent to derived addresses before we created
  them. Found addresses are automatically registered and NextAddressIndex is
  updated - no sweep needed.

Examples:
  # Scan retired addresses only (backwards compatible)
  $ vault read btc/wallets/my-wallet/scan

  # Scan 20 addresses ahead for untracked deposits
  $ vault read btc/wallets/my-wallet/scan gap=20

  # Scan both retired and ahead
  $ vault read btc/wallets/my-wallet/scan retired=true gap=20

  # Skip retired, only scan ahead
  $ vault read btc/wallets/my-wallet/scan retired=false gap=20

  # Sweep found retired funds to a fresh address
  $ vault write btc/wallets/my-wallet/scan sweep=true fee_rate=5

Parameters:
  - retired: Scan addresses below FirstActiveIndex (default: true)
  - gap: Scan N addresses beyond NextAddressIndex (default: 0)
  - sweep: Consolidate found retired funds to a fresh address (default: false)
  - fee_rate: Fee rate for sweep transaction in sat/vbyte (default: 10)

Response:
  - retired_scanned: Number of retired addresses scanned
  - retired_found: List of retired addresses with funds
  - retired_total: Total satoshis found on retired addresses
  - gap_scanned: Number of gap addresses scanned
  - gap_found: List of untracked addresses with funds
  - gap_total: Total satoshis found on untracked addresses
  - gap_registered: Addresses that were registered from gap scan
  - new_next_index: Updated NextAddressIndex after gap registration
  - sweep_*: Sweep transaction details (if sweep=true and retired funds found)
  - total_found: Combined total from both scans

Best practices:
  - Run gap=20 periodically to detect deposits to untracked addresses
  - Run retired scan after compaction to verify no funds were missed
  - Use sweep=true only for retired funds (gap funds are auto-registered)
`
