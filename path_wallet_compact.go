package btc

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/djschnei21/vault-plugin-btc/electrum"
	"github.com/djschnei21/vault-plugin-btc/wallet"
)

// CompactionResult holds the results of a compaction operation
type CompactionResult struct {
	PreviousFirstActive uint32
	NewFirstActive      uint32
	AddressesDeleted    int
	AddressesRemaining  int
}

func pathWalletCompact(b *btcBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "wallets/" + framework.GenericNameRegex("name") + "/compact",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "btc",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the wallet",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathWalletCompact,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "compact",
					},
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathWalletCompact,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "compact",
					},
				},
			},
			ExistenceCheck:  b.pathWalletCompactExistenceCheck,
			HelpSynopsis:    pathWalletCompactHelpSynopsis,
			HelpDescription: pathWalletCompactHelpDescription,
		},
	}
}

func (b *btcBackend) pathWalletCompactExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	return false, nil
}

func (b *btcBackend) pathWalletCompact(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	b.Logger().Debug("compacting wallet", "wallet", name)

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

	result, err := b.runCompaction(ctx, req.Storage, name, network, client)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"previous_first_active": result.PreviousFirstActive,
			"new_first_active":      result.NewFirstActive,
			"addresses_deleted":     result.AddressesDeleted,
			"addresses_remaining":   result.AddressesRemaining,
		},
	}, nil
}

// runCompaction performs the actual compaction work and can be called from multiple places
func (b *btcBackend) runCompaction(ctx context.Context, s logical.Storage, walletName string, network string, client *electrum.Client) (*CompactionResult, error) {
	w, err := getWallet(ctx, s, walletName)
	if err != nil {
		return nil, err
	}

	if w == nil {
		return nil, fmt.Errorf("wallet %q not found", walletName)
	}

	// Get all stored addresses
	addresses, err := getStoredAddresses(ctx, s, walletName)
	if err != nil {
		return nil, err
	}

	originalFirstActive := w.FirstActiveIndex
	deletedCount := 0
	newFirstActive := w.FirstActiveIndex

	// Find the new first active index by checking each address from the current first active
	// An address can be compacted if: spent=true AND balance=0
	for idx := w.FirstActiveIndex; idx < w.NextAddressIndex; idx++ {
		// Find stored address for this index
		var addr *storedAddress
		for i := range addresses {
			if addresses[i].Index == idx {
				addr = &addresses[i]
				break
			}
		}

		// If no stored address, regenerate to check
		if addr == nil {
			addrInfo, err := wallet.GenerateAddressInfoForType(w.Seed, network, idx, w.AddressType)
			if err != nil {
				b.Logger().Warn("failed to regenerate address", "index", idx, "error", err)
				break
			}
			addr = &storedAddress{
				Address:    addrInfo.Address,
				Index:      idx,
				ScriptHash: addrInfo.ScriptHash,
				Spent:      false, // Unknown, assume not spent
			}
		}

		// If not spent, stop here - can't compact
		if !addr.Spent {
			break
		}

		// Check balance via Electrum
		balanceResp, err := client.GetBalance(addr.ScriptHash)
		if err != nil {
			b.Logger().Warn("failed to get balance", "address", addr.Address, "error", err)
			break
		}

		// If has any balance, stop here
		if balanceResp.Confirmed > 0 || balanceResp.Unconfirmed > 0 {
			b.Logger().Debug("address has balance, stopping compaction", "address", addr.Address, "confirmed", balanceResp.Confirmed)
			break
		}

		// This address is spent and empty - can be compacted
		newFirstActive = idx + 1
	}

	// Delete address records below the new first active index
	for _, addr := range addresses {
		if addr.Index < newFirstActive {
			storageKey := fmt.Sprintf("%s%s/%d", addressStoragePrefix, walletName, addr.Index)
			if err := s.Delete(ctx, storageKey); err != nil {
				b.Logger().Warn("failed to delete address", "index", addr.Index, "error", err)
			} else {
				deletedCount++
			}
		}
	}

	// Update wallet with new first active index
	if newFirstActive != w.FirstActiveIndex {
		w.FirstActiveIndex = newFirstActive
		if err := saveWallet(ctx, s, w); err != nil {
			return nil, fmt.Errorf("failed to update wallet: %w", err)
		}
	}

	// Invalidate cache since we've been checking addresses
	b.cache.InvalidateWallet(walletName)

	b.Logger().Info("wallet compacted",
		"wallet", walletName,
		"previous_first_active", originalFirstActive,
		"new_first_active", newFirstActive,
		"addresses_deleted", deletedCount)

	return &CompactionResult{
		PreviousFirstActive: originalFirstActive,
		NewFirstActive:      newFirstActive,
		AddressesDeleted:    deletedCount,
		AddressesRemaining:  int(w.NextAddressIndex - newFirstActive),
	}, nil
}

const pathWalletCompactHelpSynopsis = `
Compact wallet by removing fully-spent empty address records.
`

const pathWalletCompactHelpDescription = `
This endpoint removes stored address records for addresses that are:
  1. Marked as spent (used as transaction inputs)
  2. Have zero balance (no UTXOs)

Since addresses can be regenerated from the wallet seed, there's no need to
store records for addresses that will never be used again. This reduces storage
and speeds up wallet operations.

Example:
  $ vault write btc/wallets/my-wallet/compact

Response:
  - previous_first_active: Previous lowest tracked address index
  - new_first_active: New lowest tracked address index after compaction
  - addresses_deleted: Number of address records removed
  - addresses_remaining: Number of address records still stored

The compaction is conservative - it stops at the first address that either:
  - Is not marked as spent
  - Has any remaining balance

This ensures no data is lost for addresses that might still be relevant.

Note: Compaction can also be triggered automatically after consolidation by
using the compact=true option on the consolidate endpoint.
`
