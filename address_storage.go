package btc

import (
	"context"
	"fmt"
	"sort"

	"github.com/hashicorp/vault/sdk/logical"
)

const addressStoragePrefix = "addresses/"

// storedAddress stores information about a generated address
type storedAddress struct {
	Address        string `json:"address"`
	Index          uint32 `json:"index"`
	DerivationPath string `json:"derivation_path"`
	ScriptHash     string `json:"scripthash"`
	Spent          bool   `json:"spent,omitempty"` // True if this address has been used as an input
}

// getStoredAddresses retrieves all stored addresses for a wallet, sorted by index
func getStoredAddresses(ctx context.Context, s logical.Storage, walletName string) ([]storedAddress, error) {
	prefix := addressStoragePrefix + walletName + "/"
	entries, err := s.List(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("error listing addresses: %w", err)
	}

	addresses := make([]storedAddress, 0, len(entries))
	for _, entry := range entries {
		stored, err := s.Get(ctx, prefix+entry)
		if err != nil {
			continue
		}
		if stored == nil {
			continue
		}

		var addr storedAddress
		if err := stored.DecodeJSON(&addr); err != nil {
			continue
		}

		addresses = append(addresses, addr)
	}

	// Sort by index for consistent ordering
	sort.Slice(addresses, func(i, j int) bool {
		return addresses[i].Index < addresses[j].Index
	})

	return addresses, nil
}

// markAddressSpent marks an address as spent (used as transaction input)
func markAddressSpent(ctx context.Context, s logical.Storage, walletName string, addressIndex uint32) error {
	storageKey := fmt.Sprintf("%s%s/%d", addressStoragePrefix, walletName, addressIndex)

	entry, err := s.Get(ctx, storageKey)
	if err != nil {
		return fmt.Errorf("error reading address: %w", err)
	}
	if entry == nil {
		return fmt.Errorf("address at index %d not found", addressIndex)
	}

	var addr storedAddress
	if err := entry.DecodeJSON(&addr); err != nil {
		return fmt.Errorf("error decoding address: %w", err)
	}

	addr.Spent = true

	newEntry, err := logical.StorageEntryJSON(storageKey, addr)
	if err != nil {
		return fmt.Errorf("error creating storage entry: %w", err)
	}

	if err := s.Put(ctx, newEntry); err != nil {
		return fmt.Errorf("error saving address: %w", err)
	}

	return nil
}

// markAddressesSpent marks multiple addresses as spent
func markAddressesSpent(ctx context.Context, s logical.Storage, walletName string, addressIndices []uint32) error {
	for _, idx := range addressIndices {
		if err := markAddressSpent(ctx, s, walletName, idx); err != nil {
			return err
		}
	}
	return nil
}
