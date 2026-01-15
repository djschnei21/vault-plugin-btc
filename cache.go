package btc

import (
	"sync"
	"time"
)

const (
	// MaxCacheAge is the maximum age before we force a status check
	// This is a safety net - normally we rely on status hash validation
	MaxCacheAge = 5 * time.Minute
)

// AddressCache holds cached data for a single address
type AddressCache struct {
	StatusHash  *string // nil means no transaction history
	Balance     BalanceInfo
	History     []TxHistoryItem
	UTXOs       []CachedUTXO
	LastUpdated time.Time
}

// BalanceInfo holds balance data for an address
type BalanceInfo struct {
	Confirmed   int64
	Unconfirmed int64
}

// TxHistoryItem represents a transaction in address history
type TxHistoryItem struct {
	TxHash string
	Height int64
}

// CachedUTXO represents a cached unspent output
type CachedUTXO struct {
	TxID   string
	Vout   uint32
	Value  int64
	Height int64
}

// WalletCache holds all cached data for a wallet
type WalletCache struct {
	Addresses   map[string]*AddressCache // keyed by address string
	BlockHeight int64                    // cached block height for confirmations
	HeightTime  time.Time                // when block height was fetched
	LastUpdated time.Time
	mu          sync.RWMutex
}

// WalletCacheManager manages caches for all wallets
type WalletCacheManager struct {
	wallets map[string]*WalletCache // keyed by wallet name
	mu      sync.RWMutex
}

// NewWalletCacheManager creates a new cache manager
func NewWalletCacheManager() *WalletCacheManager {
	return &WalletCacheManager{
		wallets: make(map[string]*WalletCache),
	}
}

// GetWalletCache gets or creates a cache for a wallet
func (m *WalletCacheManager) GetWalletCache(walletName string) *WalletCache {
	m.mu.RLock()
	cache, exists := m.wallets[walletName]
	m.mu.RUnlock()

	if exists {
		return cache
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	if cache, exists = m.wallets[walletName]; exists {
		return cache
	}

	cache = &WalletCache{
		Addresses: make(map[string]*AddressCache),
	}
	m.wallets[walletName] = cache
	return cache
}

// InvalidateWallet clears the cache for a wallet
func (m *WalletCacheManager) InvalidateWallet(walletName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.wallets, walletName)
}

// statusMatches compares two status hashes (handles nil for no history)
func statusMatches(cached, current *string) bool {
	if cached == nil && current == nil {
		return true
	}
	if cached == nil || current == nil {
		return false
	}
	return *cached == *current
}

// GetAddressCacheIfValid returns cached data if the status hash matches
// Returns nil if cache is missing, too old, or status doesn't match
func (c *WalletCache) GetAddressCacheIfValid(address string, currentStatus *string) *AddressCache {
	c.mu.RLock()
	defer c.mu.RUnlock()

	addrCache, exists := c.Addresses[address]
	if !exists {
		return nil
	}

	// Safety check: don't use cache older than MaxCacheAge regardless of status
	if time.Since(addrCache.LastUpdated) > MaxCacheAge {
		return nil
	}

	// Check if status hash matches
	if !statusMatches(addrCache.StatusHash, currentStatus) {
		return nil
	}

	return addrCache
}

// SetAddressCache updates cached data for an address with its status hash
func (c *WalletCache) SetAddressCache(address string, status *string, balance BalanceInfo, history []TxHistoryItem, utxos []CachedUTXO) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.Addresses[address] = &AddressCache{
		StatusHash:  status,
		Balance:     balance,
		History:     history,
		UTXOs:       utxos,
		LastUpdated: time.Now(),
	}
	c.LastUpdated = time.Now()
}

// InvalidateAddress removes a single address from cache
func (c *WalletCache) InvalidateAddress(address string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.Addresses, address)
}

// GetBlockHeight returns cached block height if recent, 0 otherwise
func (c *WalletCache) GetBlockHeight() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Block height cache is valid for 30 seconds
	if time.Since(c.HeightTime) < 30*time.Second {
		return c.BlockHeight
	}
	return 0
}

// SetBlockHeight updates the cached block height
func (c *WalletCache) SetBlockHeight(height int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.BlockHeight = height
	c.HeightTime = time.Now()
}

// GetAddressCount returns the number of cached addresses
func (c *WalletCache) GetAddressCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.Addresses)
}
