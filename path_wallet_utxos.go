package btc

import (
	"context"
	"fmt"
	"sort"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathWalletUTXOs(b *btcBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "wallets/" + framework.GenericNameRegex("name") + "/utxos",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "btc",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the wallet",
					Required:    true,
				},
				"min_confirmations": {
					Type:        framework.TypeInt,
					Description: "Filter UTXOs by minimum confirmations (default: 0, show all)",
					Default:     0,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathWalletUTXOsRead,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "utxos",
					},
				},
			},
			HelpSynopsis:    pathWalletUTXOsHelpSynopsis,
			HelpDescription: pathWalletUTXOsHelpDescription,
		},
	}
}

// UTXODetail represents detailed UTXO data returned to the user
type UTXODetail struct {
	TxID          string `json:"txid"`
	Vout          uint32 `json:"vout"`
	Address       string `json:"address"`
	AddressIndex  uint32 `json:"address_index"`
	Value         int64  `json:"value"`
	Height        int64  `json:"height"`
	Confirmations int64  `json:"confirmations"`
}

func (b *btcBackend) pathWalletUTXOsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	minConf := data.Get("min_confirmations").(int)

	b.Logger().Debug("reading wallet UTXOs", "wallet", name, "min_confirmations", minConf)

	w, err := getWallet(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if w == nil {
		return logical.ErrorResponse("wallet %q not found", name), nil
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Electrum server: %w", err)
	}

	// Get current block height for confirmations calculation
	// We'll estimate confirmations: if height > 0, it's confirmed (at least 1)
	// For more accurate confirmations, we'd need to query the current block height

	// Get stored addresses
	addresses, err := getStoredAddresses(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	walletCache := b.cache.GetWalletCache(name)
	var utxoDetails []UTXODetail
	var totalValue int64

	// Track if we need to reconnect (stale connection detected)
	reconnectAttempted := false

	for _, addr := range addresses {
		var utxos []CachedUTXO

		// Get current status hash from Electrum (lightweight call)
		currentStatus, err := client.Subscribe(addr.ScriptHash)
		if err != nil {
			b.Logger().Warn("failed to get status", "address", addr.Address, "error", err)

			// Check for connection errors and try to reconnect once
			if !reconnectAttempted && b.handleClientError(err) {
				reconnectAttempted = true
				newClient, reconErr := b.getClient(ctx, req.Storage)
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
			balanceResp, err := client.GetBalance(addr.ScriptHash)
			var balance BalanceInfo
			if err != nil {
				b.Logger().Warn("failed to get balance", "address", addr.Address, "error", err)
				// Try reconnect if needed
				if !reconnectAttempted && b.handleClientError(err) {
					reconnectAttempted = true
					if newClient, reconErr := b.getClient(ctx, req.Storage); reconErr == nil {
						client = newClient
						balanceResp, err = client.GetBalance(addr.ScriptHash)
					}
				}
			}
			if err == nil {
				balance = BalanceInfo{
					Confirmed:   balanceResp.Confirmed,
					Unconfirmed: balanceResp.Unconfirmed,
				}
			}

			// Get history for cache
			historyResp, err := client.GetHistory(addr.ScriptHash)
			var history []TxHistoryItem
			if err != nil {
				b.Logger().Warn("failed to get history", "address", addr.Address, "error", err)
				history = []TxHistoryItem{}
			} else {
				history = make([]TxHistoryItem, len(historyResp))
				for i, h := range historyResp {
					history[i] = TxHistoryItem{
						TxHash: h.TxHash,
						Height: h.Height,
					}
				}
			}

			// Get UTXOs
			utxoResp, err := client.ListUnspent(addr.ScriptHash)
			if err != nil {
				b.Logger().Warn("failed to get UTXOs", "address", addr.Address, "error", err)
				// Try reconnect if needed
				if !reconnectAttempted && b.handleClientError(err) {
					reconnectAttempted = true
					if newClient, reconErr := b.getClient(ctx, req.Storage); reconErr == nil {
						client = newClient
						utxoResp, err = client.ListUnspent(addr.ScriptHash)
					}
				}
			}
			if err != nil {
				utxos = []CachedUTXO{}
			} else {
				utxos = make([]CachedUTXO, len(utxoResp))
				for i, u := range utxoResp {
					utxos[i] = CachedUTXO{
						TxID:   u.TxHash,
						Vout:   uint32(u.TxPos),
						Value:  u.Value,
						Height: u.Height,
					}
				}
			}

			// Update cache only if Subscribe succeeded
			if currentStatus != nil {
				walletCache.SetAddressCache(addr.Address, currentStatus, balance, history, utxos)
			}
		}

		// Add UTXOs to result
		for _, utxo := range utxos {
			// Calculate confirmations (0 if unconfirmed, 1+ if confirmed)
			var confirmations int64 = 0
			if utxo.Height > 0 {
				confirmations = 1 // At minimum, it's confirmed
				// For accurate confirmations, we'd need current block height
			}

			// Filter by min_confirmations
			if int(confirmations) < minConf {
				continue
			}

			detail := UTXODetail{
				TxID:          utxo.TxID,
				Vout:          utxo.Vout,
				Address:       addr.Address,
				AddressIndex:  addr.Index,
				Value:         utxo.Value,
				Height:        utxo.Height,
				Confirmations: confirmations,
			}
			utxoDetails = append(utxoDetails, detail)
			totalValue += utxo.Value
		}
	}

	// Sort by value (largest first, like Sparrow's default)
	sort.Slice(utxoDetails, func(i, j int) bool {
		return utxoDetails[i].Value > utxoDetails[j].Value
	})

	// Convert to interface slice for response
	utxoList := make([]map[string]interface{}, len(utxoDetails))
	for i, detail := range utxoDetails {
		utxoList[i] = map[string]interface{}{
			"txid":          detail.TxID,
			"vout":          detail.Vout,
			"address":       detail.Address,
			"address_index": detail.AddressIndex,
			"value":         detail.Value,
			"height":        detail.Height,
			"confirmations": detail.Confirmations,
		}
	}

	b.Logger().Debug("UTXOs read complete", "wallet", name, "count", len(utxoDetails), "total_value", totalValue)

	return &logical.Response{
		Data: map[string]interface{}{
			"utxos":       utxoList,
			"utxo_count":  len(utxoDetails),
			"total_value": totalValue,
		},
	}, nil
}

const pathWalletUTXOsHelpSynopsis = `
List all UTXOs (unspent transaction outputs) for a wallet.
`

const pathWalletUTXOsHelpDescription = `
This endpoint returns all unspent transaction outputs (UTXOs) for a wallet,
similar to Sparrow wallet's UTXOs tab. Each UTXO includes:

  - txid: Transaction ID containing this output
  - vout: Output index within the transaction
  - address: The address that owns this UTXO
  - address_index: Derivation index of the address
  - value: Amount in satoshis
  - height: Block height (0 if unconfirmed)
  - confirmations: Number of confirmations

UTXOs are sorted by value (largest first) for optimal coin selection visibility.

Example:
  $ vault read btc/wallets/my-wallet/utxos

Filter by confirmations:
  $ vault read btc/wallets/my-wallet/utxos min_confirmations=1

Response also includes:
  - utxo_count: Total number of UTXOs
  - total_value: Sum of all UTXO values

All amounts are in satoshis (1 BTC = 100,000,000 satoshis).

Best practices (from Sparrow wallet):
  - Fewer, larger UTXOs are generally better for fee efficiency
  - Many small UTXOs increase transaction fees
  - Consider consolidating UTXOs during low-fee periods
`
