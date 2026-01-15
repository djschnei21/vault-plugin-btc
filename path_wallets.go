package btc

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/dan/vault-plugin-secrets-btc/wallet"
)

const walletsStoragePrefix = "wallets/"

// AddressType constants
const (
	AddressTypeP2WPKH = "p2wpkh" // Native SegWit (BIP84)
	AddressTypeP2TR   = "p2tr"   // Taproot (BIP86)
)

// btcWallet stores the wallet configuration
type btcWallet struct {
	Name             string    `json:"name"`
	Description      string    `json:"description,omitempty"`
	Seed             []byte    `json:"seed"`
	AddressType      string    `json:"address_type"` // p2wpkh or p2tr (default: p2tr)
	NextAddressIndex uint32    `json:"next_address_index"`
	FirstActiveIndex uint32    `json:"first_active_index"` // Addresses below this are spent+empty
	CreatedAt        time.Time `json:"created_at"`
}

func pathWallets(b *btcBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "wallets/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "btc",
				OperationSuffix: "wallets",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathWalletsList,
				},
			},
			HelpSynopsis:    pathWalletsListHelpSynopsis,
			HelpDescription: pathWalletsListHelpDescription,
		},
		{
			Pattern: "wallets/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "btc",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the wallet",
					Required:    true,
				},
				"description": {
					Type:        framework.TypeString,
					Description: "Optional description for this wallet",
				},
				"address_type": {
					Type:        framework.TypeString,
					Description: "Address type: p2tr (Taproot, default) or p2wpkh (SegWit)",
					Default:     "p2tr",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathWalletsRead,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "wallet",
					},
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathWalletsWrite,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "wallet",
					},
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathWalletsWrite,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "wallet",
					},
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathWalletsDelete,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "wallet",
					},
				},
			},
			ExistenceCheck:  b.pathWalletsExistenceCheck,
			HelpSynopsis:    pathWalletsHelpSynopsis,
			HelpDescription: pathWalletsHelpDescription,
		},
	}
}

func (b *btcBackend) pathWalletsList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("listing wallets")
	entries, err := req.Storage.List(ctx, walletsStoragePrefix)
	if err != nil {
		return nil, fmt.Errorf("error listing wallets: %w", err)
	}

	b.Logger().Debug("wallets listed", "count", len(entries))
	return logical.ListResponse(entries), nil
}

func (b *btcBackend) pathWalletsExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	name := data.Get("name").(string)
	w, err := getWallet(ctx, req.Storage, name)
	if err != nil {
		return false, err
	}
	return w != nil, nil
}

func (b *btcBackend) pathWalletsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	b.Logger().Debug("reading wallet", "name", name)

	w, err := getWallet(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if w == nil {
		b.Logger().Debug("wallet not found", "name", name)
		return nil, nil
	}

	network, err := getNetwork(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// Get Electrum client for balance and address checks
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Electrum server: %w", err)
	}

	// Get all stored addresses and calculate balance
	addresses, err := getStoredAddresses(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	var confirmed, unconfirmed int64
	var receiveAddress string
	var receiveIndex uint32

	// Use cache for efficient data fetching
	walletCache := b.cache.GetWalletCache(name)

	// Track if we need to reconnect (stale connection detected)
	reconnectAttempted := false

	// First pass: find an unused address and aggregate balances
	b.Logger().Debug("checking addresses for wallet", "wallet", name, "address_count", len(addresses))
	for _, addr := range addresses {
		var balance BalanceInfo
		var historyCount int

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
					// Retry this address with fresh connection
					currentStatus, err = client.Subscribe(addr.ScriptHash)
					if err != nil {
						b.Logger().Warn("failed to get status after reconnect", "address", addr.Address, "error", err)
					}
				}
			}
		}

		// Only use cache if Subscribe succeeded (currentStatus is valid)
		// When Subscribe fails, currentStatus is nil which could incorrectly match
		// cached entries for addresses that had no transaction history
		var cached *AddressCache
		if err == nil {
			cached = walletCache.GetAddressCacheIfValid(addr.Address, currentStatus)
		}

		if cached != nil {
			b.Logger().Debug("cache hit (status match)", "address", addr.Address)
			balance = cached.Balance
			historyCount = len(cached.History)
		} else {
			// Cache miss, stale, or Subscribe failed - fetch from Electrum
			b.Logger().Debug("fetching from Electrum", "address", addr.Address, "subscribe_failed", err != nil)

			// Get balance
			balanceResp, balErr := client.GetBalance(addr.ScriptHash)
			if balErr != nil {
				b.Logger().Warn("failed to get balance", "address", addr.Address, "error", balErr)
				// Try reconnect if needed
				if !reconnectAttempted && b.handleClientError(balErr) {
					reconnectAttempted = true
					if newClient, reconErr := b.getClient(ctx, req.Storage); reconErr == nil {
						client = newClient
						balanceResp, balErr = client.GetBalance(addr.ScriptHash)
					}
				}
			}
			if balErr == nil {
				balance = BalanceInfo{
					Confirmed:   balanceResp.Confirmed,
					Unconfirmed: balanceResp.Unconfirmed,
				}
			}

			// Get history
			var history []TxHistoryItem
			historyResp, histErr := client.GetHistory(addr.ScriptHash)
			if histErr != nil {
				b.Logger().Warn("failed to get history", "address", addr.Address, "error", histErr)
			} else {
				history = make([]TxHistoryItem, len(historyResp))
				for i, h := range historyResp {
					history[i] = TxHistoryItem{TxHash: h.TxHash, Height: h.Height}
				}
				historyCount = len(history)
			}

			// Get UTXOs for cache completeness
			var utxos []CachedUTXO
			utxoResp, utxoErr := client.ListUnspent(addr.ScriptHash)
			if utxoErr == nil {
				utxos = make([]CachedUTXO, len(utxoResp))
				for i, u := range utxoResp {
					utxos[i] = CachedUTXO{TxID: u.TxHash, Vout: uint32(u.TxPos), Value: u.Value, Height: u.Height}
				}
			}

			// Only update cache if we got valid data (Subscribe succeeded)
			if err == nil {
				walletCache.SetAddressCache(addr.Address, currentStatus, balance, history, utxos)
			}
		}

		confirmed += balance.Confirmed
		unconfirmed += balance.Unconfirmed

		// Check if this address can be used for receiving
		// Skip if: 1) already marked spent, OR 2) has any transaction history
		if receiveAddress == "" {
			if addr.Spent {
				// Fast path: address already marked as spent, skip without Electrum check
				b.Logger().Debug("address marked as spent, skipping", "address", addr.Address, "index", addr.Index)
			} else if historyCount > 0 {
				// Address has transaction history - should not be reused
				b.Logger().Debug("address has history, skipping", "address", addr.Address, "tx_count", historyCount)
			} else {
				// Address is fresh - can be used for receiving
				b.Logger().Debug("found unused address", "address", addr.Address, "index", addr.Index)
				receiveAddress = addr.Address
				receiveIndex = addr.Index
			}
		}
	}

	// Log if no unused address is available (user must generate via POST /addresses)
	if receiveAddress == "" {
		b.Logger().Debug("no unused address available", "wallet", name, "address_count", len(addresses))
	}

	respData := map[string]interface{}{
		"name":          w.Name,
		"network":       network,
		"address_type":  w.AddressType,
		"confirmed":     confirmed,
		"unconfirmed":   unconfirmed,
		"total":         confirmed + unconfirmed,
		"address_count": len(addresses),
		"created_at":    w.CreatedAt.Format(time.RFC3339),
	}

	if receiveAddress != "" {
		respData["receive_address"] = receiveAddress
		respData["receive_index"] = receiveIndex
	} else {
		respData["receive_address"] = nil
		respData["warning"] = "no unused address available - generate one with: vault write btc/wallets/" + name + "/addresses"
	}

	if w.Description != "" {
		respData["description"] = w.Description
	}

	return &logical.Response{Data: respData}, nil
}

func (b *btcBackend) pathWalletsWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	b.Logger().Debug("writing wallet", "name", name, "operation", req.Operation)

	w, err := getWallet(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	createOperation := req.Operation == logical.CreateOperation

	if w == nil {
		if !createOperation {
			return nil, fmt.Errorf("wallet %q not found during update operation", name)
		}

		// Get and validate address type
		addressType := data.Get("address_type").(string)
		if addressType != AddressTypeP2TR && addressType != AddressTypeP2WPKH {
			return logical.ErrorResponse("invalid address_type %q: must be %q or %q", addressType, AddressTypeP2TR, AddressTypeP2WPKH), nil
		}

		b.Logger().Info("creating new wallet", "name", name, "address_type", addressType)
		// Generate new seed for new wallet
		seed, err := wallet.GenerateSeed()
		if err != nil {
			return nil, fmt.Errorf("failed to generate seed: %w", err)
		}

		w = &btcWallet{
			Name:             name,
			Seed:             seed,
			AddressType:      addressType,
			NextAddressIndex: 0,
			CreatedAt:        time.Now().UTC(),
		}
	}

	// Handle description (can be set on create or update)
	if description, ok := data.GetOk("description"); ok {
		w.Description = description.(string)
	}

	// Get network for address generation
	network, err := getNetwork(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// For create operations, generate and store the first 5 addresses
	const initialAddressCount = 5
	if createOperation {
		for i := uint32(0); i < initialAddressCount; i++ {
			addrInfo, err := wallet.GenerateAddressInfoForType(w.Seed, network, i, w.AddressType)
			if err != nil {
				return nil, fmt.Errorf("failed to generate address %d: %w", i, err)
			}

			stored := &storedAddress{
				Address:        addrInfo.Address,
				Index:          addrInfo.Index,
				DerivationPath: addrInfo.DerivationPath,
				ScriptHash:     addrInfo.ScriptHash,
			}

			storageKey := fmt.Sprintf("%s%s/%d", addressStoragePrefix, w.Name, i)
			entry, err := logical.StorageEntryJSON(storageKey, stored)
			if err != nil {
				return nil, fmt.Errorf("failed to create storage entry: %w", err)
			}

			if err := req.Storage.Put(ctx, entry); err != nil {
				return nil, fmt.Errorf("failed to store address %d: %w", i, err)
			}
		}

		w.NextAddressIndex = initialAddressCount
	}

	// Save wallet
	if err := saveWallet(ctx, req.Storage, w); err != nil {
		return nil, err
	}

	// Get stored addresses for response
	addresses, err := getStoredAddresses(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	// For a new wallet, balance is 0 and receive address is the first address
	var receiveAddress string
	var receiveIndex uint32
	if len(addresses) > 0 {
		receiveAddress = addresses[0].Address
		receiveIndex = addresses[0].Index
	}

	respData := map[string]interface{}{
		"name":            w.Name,
		"network":         network,
		"address_type":    w.AddressType,
		"confirmed":       int64(0),
		"unconfirmed":     int64(0),
		"total":           int64(0),
		"address_count":   len(addresses),
		"receive_address": receiveAddress,
		"receive_index":   receiveIndex,
		"created_at":      w.CreatedAt.Format(time.RFC3339),
	}

	if w.Description != "" {
		respData["description"] = w.Description
	}

	return &logical.Response{Data: respData}, nil
}

func (b *btcBackend) pathWalletsDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	b.Logger().Debug("deleting wallet", "name", name)

	// Invalidate cache
	b.cache.InvalidateWallet(name)

	// Delete the wallet
	if err := req.Storage.Delete(ctx, walletsStoragePrefix+name); err != nil {
		return nil, fmt.Errorf("error deleting wallet: %w", err)
	}

	// Delete associated addresses
	addressPrefix := addressStoragePrefix + name + "/"
	addresses, err := req.Storage.List(ctx, addressPrefix)
	if err != nil {
		return nil, fmt.Errorf("error listing addresses: %w", err)
	}

	for _, addr := range addresses {
		if err := req.Storage.Delete(ctx, addressPrefix+addr); err != nil {
			return nil, fmt.Errorf("error deleting address: %w", err)
		}
	}

	b.Logger().Info("wallet deleted", "name", name, "addresses_deleted", len(addresses))
	return nil, nil
}

// getWallet retrieves a wallet from storage
func getWallet(ctx context.Context, s logical.Storage, name string) (*btcWallet, error) {
	entry, err := s.Get(ctx, walletsStoragePrefix+name)
	if err != nil {
		return nil, fmt.Errorf("error retrieving wallet: %w", err)
	}

	if entry == nil {
		return nil, nil
	}

	w := new(btcWallet)
	if err := entry.DecodeJSON(w); err != nil {
		return nil, fmt.Errorf("error decoding wallet: %w", err)
	}

	return w, nil
}

// saveWallet saves a wallet to storage
func saveWallet(ctx context.Context, s logical.Storage, w *btcWallet) error {
	entry, err := logical.StorageEntryJSON(walletsStoragePrefix+w.Name, w)
	if err != nil {
		return fmt.Errorf("error creating storage entry: %w", err)
	}

	if err := s.Put(ctx, entry); err != nil {
		return fmt.Errorf("error saving wallet: %w", err)
	}

	return nil
}

const pathWalletsListHelpSynopsis = `
List all wallets.
`

const pathWalletsListHelpDescription = `
This endpoint lists all configured wallets in the Bitcoin secrets engine.
`

const pathWalletsHelpSynopsis = `
Manage Bitcoin wallets.
`

const pathWalletsHelpDescription = `
This endpoint manages Bitcoin wallets. Each wallet is an HD wallet with its own
seed and address derivation. All wallets use the network configured at the mount
level (btc/config).

To create a new wallet:
  $ vault write btc/wallets/my-wallet description="Treasury"

To view wallet info and balance:
  $ vault read btc/wallets/my-wallet

To delete a wallet:
  $ vault delete btc/wallets/my-wallet

WARNING: Deleting a wallet permanently destroys the seed. Ensure all funds have
been transferred before deletion.
`
