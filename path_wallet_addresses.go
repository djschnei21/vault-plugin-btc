package btc

import (
	"context"
	"fmt"
	"sort"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/djschnei21/vault-plugin-btc/wallet"
)

func pathWalletAddresses(b *btcBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "wallets/" + framework.GenericNameRegex("name") + "/addresses",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "btc",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the wallet",
					Required:    true,
				},
				"count": {
					Type:        framework.TypeInt,
					Description: "Number of unused addresses to generate (default: 1)",
					Default:     1,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathWalletAddressesRead,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "addresses",
					},
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathWalletAddressesWrite,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "addresses-generate",
					},
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathWalletAddressesWrite,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "addresses-generate",
					},
				},
			},
			ExistenceCheck:  b.pathWalletAddressesExistenceCheck,
			HelpSynopsis:    pathWalletAddressesHelpSynopsis,
			HelpDescription: pathWalletAddressesHelpDescription,
		},
	}
}

// AddressInfo represents address data returned to the user
type AddressInfo struct {
	Address        string `json:"address"`
	Index          uint32 `json:"index"`
	DerivationPath string `json:"derivation_path"`
	Confirmed      int64  `json:"confirmed"`
	Unconfirmed    int64  `json:"unconfirmed"`
	Total          int64  `json:"total"`
	TxCount        int    `json:"tx_count"`
	Used           bool   `json:"used"`
	Spent          bool   `json:"spent"` // True if address was used as transaction input
}

func (b *btcBackend) pathWalletAddressesRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	b.Logger().Debug("reading wallet addresses", "wallet", name)

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

	// Get stored addresses
	addresses, err := getStoredAddresses(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	walletCache := b.cache.GetWalletCache(name)
	var addressInfos []AddressInfo

	for _, addr := range addresses {
		var balance BalanceInfo
		var history []TxHistoryItem
		var utxos []CachedUTXO

		// Get current status hash from Electrum (lightweight call)
		currentStatus, subscribeErr := client.Subscribe(addr.ScriptHash)
		subscribeSucceeded := subscribeErr == nil
		if subscribeErr != nil {
			b.Logger().Warn("failed to get status", "address", addr.Address, "error", subscribeErr)
		}

		// Only check cache if Subscribe succeeded - nil status from error could cause false cache hits
		// (nil status is valid for addresses with no tx history, so we can't distinguish error from no-history)
		var cached *AddressCache
		if subscribeSucceeded {
			cached = walletCache.GetAddressCacheIfValid(addr.Address, currentStatus)
		}

		if cached != nil {
			b.Logger().Debug("cache hit (status match)", "address", addr.Address)
			balance = cached.Balance
			history = cached.History
		} else {
			// Cache miss or stale - fetch from Electrum
			b.Logger().Debug("cache miss, fetching from Electrum", "address", addr.Address)

			// Get balance
			balanceResp, err := client.GetBalance(addr.ScriptHash)
			if err != nil {
				b.Logger().Warn("failed to get balance", "address", addr.Address, "error", err)
				balance = BalanceInfo{}
			} else {
				balance = BalanceInfo{
					Confirmed:   balanceResp.Confirmed,
					Unconfirmed: balanceResp.Unconfirmed,
				}
			}

			// Get history
			historyResp, err := client.GetHistory(addr.ScriptHash)
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

			// Get UTXOs for cache
			utxoResp, err := client.ListUnspent(addr.ScriptHash)
			if err != nil {
				b.Logger().Warn("failed to get UTXOs", "address", addr.Address, "error", err)
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

			// Only update cache if Subscribe succeeded - prevents caching with nil status from errors
			if subscribeSucceeded {
				walletCache.SetAddressCache(addr.Address, currentStatus, balance, history, utxos)
			}
		}

		info := AddressInfo{
			Address:        addr.Address,
			Index:          addr.Index,
			DerivationPath: addr.DerivationPath,
			Confirmed:      balance.Confirmed,
			Unconfirmed:    balance.Unconfirmed,
			Total:          balance.Confirmed + balance.Unconfirmed,
			TxCount:        len(history),
			Used:           len(history) > 0,
			Spent:          addr.Spent,
		}
		addressInfos = append(addressInfos, info)
	}

	// Sort by index
	sort.Slice(addressInfos, func(i, j int) bool {
		return addressInfos[i].Index < addressInfos[j].Index
	})

	// Calculate totals
	var totalConfirmed, totalUnconfirmed int64
	var usedCount, unusedCount int
	for _, info := range addressInfos {
		totalConfirmed += info.Confirmed
		totalUnconfirmed += info.Unconfirmed
		if info.Used {
			usedCount++
		} else {
			unusedCount++
		}
	}

	// Convert to interface slice for response
	addressList := make([]map[string]interface{}, len(addressInfos))
	for i, info := range addressInfos {
		addressList[i] = map[string]interface{}{
			"address":         info.Address,
			"index":           info.Index,
			"derivation_path": info.DerivationPath,
			"confirmed":       info.Confirmed,
			"unconfirmed":     info.Unconfirmed,
			"total":           info.Total,
			"tx_count":        info.TxCount,
			"used":            info.Used,
			"spent":           info.Spent,
		}
	}

	b.Logger().Debug("addresses read complete", "wallet", name, "count", len(addressInfos), "used", usedCount, "unused", unusedCount)

	return &logical.Response{
		Data: map[string]interface{}{
			"addresses":         addressList,
			"address_count":     len(addressInfos),
			"used_count":        usedCount,
			"unused_count":      unusedCount,
			"total_confirmed":   totalConfirmed,
			"total_unconfirmed": totalUnconfirmed,
			"total":             totalConfirmed + totalUnconfirmed,
		},
	}, nil
}

func (b *btcBackend) pathWalletAddressesExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	return false, nil
}

func (b *btcBackend) pathWalletAddressesWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	count := data.Get("count").(int)

	b.Logger().Debug("generating addresses", "wallet", name, "count", count)

	if count < 1 {
		return logical.ErrorResponse("count must be at least 1"), nil
	}

	if count > 100 {
		return logical.ErrorResponse("count must not exceed 100"), nil
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

	// Get Electrum client for checking address usage
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Electrum server: %w", err)
	}

	// Get existing addresses
	addresses, err := getStoredAddresses(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	walletCache := b.cache.GetWalletCache(name)
	var unusedAddresses []map[string]interface{}

	// First, find unused addresses among existing ones
	for _, addr := range addresses {
		if len(unusedAddresses) >= count {
			break
		}

		// Skip spent addresses
		if addr.Spent {
			continue
		}

		// Check if address has history
		var historyCount int
		currentStatus, err := client.Subscribe(addr.ScriptHash)
		if err != nil {
			b.Logger().Warn("failed to get status", "address", addr.Address, "error", err)
		}

		cached := walletCache.GetAddressCacheIfValid(addr.Address, currentStatus)
		if cached != nil {
			historyCount = len(cached.History)
		} else {
			historyResp, err := client.GetHistory(addr.ScriptHash)
			if err != nil {
				b.Logger().Warn("failed to get history", "address", addr.Address, "error", err)
			} else {
				historyCount = len(historyResp)
			}
		}

		// Only include unused addresses
		if historyCount == 0 {
			unusedAddresses = append(unusedAddresses, map[string]interface{}{
				"address":         addr.Address,
				"index":           addr.Index,
				"derivation_path": addr.DerivationPath,
			})
		}
	}

	// Generate new addresses if we need more
	for len(unusedAddresses) < count {
		addrInfo, err := wallet.GenerateAddressInfoForType(w.Seed, network, w.NextAddressIndex, w.AddressType)
		if err != nil {
			return nil, fmt.Errorf("failed to generate address: %w", err)
		}

		// Store the new address
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

		unusedAddresses = append(unusedAddresses, map[string]interface{}{
			"address":         addrInfo.Address,
			"index":           addrInfo.Index,
			"derivation_path": addrInfo.DerivationPath,
		})

		w.NextAddressIndex++
	}

	// Save wallet with updated index
	if err := saveWallet(ctx, req.Storage, w); err != nil {
		return nil, fmt.Errorf("failed to update wallet: %w", err)
	}

	b.Logger().Debug("addresses generated", "wallet", name, "count", len(unusedAddresses))

	return &logical.Response{
		Data: map[string]interface{}{
			"addresses": unusedAddresses,
			"count":     len(unusedAddresses),
		},
	}, nil
}

const pathWalletAddressesHelpSynopsis = `
List or generate addresses for a wallet.
`

const pathWalletAddressesHelpDescription = `
READ: List all addresses for a wallet with their balances.

This returns all generated addresses for a wallet, similar to Sparrow
wallet's Addresses tab. Each address includes:

  - address: The Bitcoin address
  - index: The derivation index
  - derivation_path: Full BIP84 derivation path
  - confirmed: Confirmed balance in satoshis
  - unconfirmed: Unconfirmed balance in satoshis
  - total: Total balance (confirmed + unconfirmed)
  - tx_count: Number of transactions involving this address
  - used: Whether the address has any transaction history
  - spent: Whether the address was used as a transaction input (will never
           be used for receiving again to preserve privacy)

Example:
  $ vault read btc/wallets/my-wallet/addresses

Response also includes summary totals:
  - address_count: Total number of addresses
  - used_count: Number of addresses with transaction history
  - unused_count: Number of addresses without transaction history
  - total_confirmed: Sum of all confirmed balances
  - total_unconfirmed: Sum of all unconfirmed balances
  - total: Total wallet balance

WRITE: Generate multiple unused receive addresses.

Parameters:
  - count: Number of unused addresses to return (default: 1, max: 100)

This will first return any existing unused addresses, then generate new ones
if needed to reach the requested count. Addresses that are marked as spent
or have any transaction history are excluded.

Example - Get 5 unused addresses:
  $ vault write btc/wallets/my-wallet/addresses count=5

Response:
  - addresses: List of unused addresses with their derivation info
  - count: Number of addresses returned

All amounts are in satoshis (1 BTC = 100,000,000 satoshis).
`
