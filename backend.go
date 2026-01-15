package btc

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/dan/vault-plugin-secrets-btc/electrum"
)

// btcBackend defines the backend for the Bitcoin secrets engine
type btcBackend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *electrum.Client
	cache  *WalletCacheManager
}

// Factory creates a new backend instance
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func backend() *btcBackend {
	b := &btcBackend{
		cache: NewWalletCacheManager(),
	}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config",
				"wallets/*",
			},
		},
		Paths: framework.PathAppend(
			pathConfig(b),
			pathWallets(b),
			pathWalletAddresses(b),
			pathWalletUTXOs(b),
			pathWalletQR(b),
			pathWalletSend(b),
			pathWalletPSBT(b),
			pathWalletConsolidate(b),
			pathWalletCompact(b),
			pathWalletScan(b),
		),
		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}

	return b
}

// invalidate resets the client when configuration changes
func (b *btcBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

// reset clears the cached Electrum client
func (b *btcBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	if b.client != nil {
		b.Logger().Debug("closing Electrum connection")
		b.client.Close()
		b.client = nil
	}
}

// isConnectionError checks if an error indicates a broken connection
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "EOF") ||
		strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "i/o timeout")
}

// handleClientError checks if an error is a connection error and resets the client if so
// Returns true if the client was reset (caller should retry with a fresh client)
func (b *btcBackend) handleClientError(err error) bool {
	if isConnectionError(err) {
		b.Logger().Warn("detected stale connection, resetting client", "error", err)
		b.reset()
		return true
	}
	return false
}

// getClient returns the Electrum client, creating one if necessary
func (b *btcBackend) getClient(ctx context.Context, s logical.Storage) (*electrum.Client, error) {
	b.lock.RLock()
	if b.client != nil {
		b.lock.RUnlock()
		return b.client, nil
	}
	b.lock.RUnlock()

	b.lock.Lock()
	defer b.lock.Unlock()

	// Double-check after acquiring write lock
	if b.client != nil {
		return b.client, nil
	}

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}

	network := "mainnet"
	if config != nil && config.Network != "" {
		network = config.Network
	}

	// Determine which server to use
	var serverURL string
	if config != nil && config.ElectrumURL != "" {
		// User explicitly configured a server
		serverURL = config.ElectrumURL
	} else {
		// Use random server from pool for this network
		serverURL = getRandomServer(network)
		if serverURL == "" {
			return nil, fmt.Errorf("no default Electrum servers configured for network %q - please set electrum_url in config", network)
		}
	}

	b.Logger().Debug("connecting to Electrum server", "url", serverURL, "network", network)
	client, err := electrum.NewClient(serverURL)
	if err != nil {
		b.Logger().Warn("failed to connect to Electrum server", "url", serverURL, "error", err)
		return nil, err
	}

	b.Logger().Info("connected to Electrum server", "url", serverURL, "network", network)
	b.client = client
	return b.client, nil
}

const backendHelp = `
The Bitcoin secrets engine provides secure storage and management of Bitcoin
wallets for custodial operations.

Each wallet is an HD wallet with automatic address management. The engine
supports:

  - Wallet creation and balance queries
  - Receiving with automatic address reuse prevention
  - Sending with fee estimation
  - PSBT (Partially Signed Bitcoin Transaction) for complex operations
  - UTXO management and consolidation

Configure the engine with an Electrum server URL and choose between mainnet,
testnet4, or custom signet networks.

Endpoints:
  btc/wallets                     - List/create/delete wallets
  btc/wallets/:name               - Wallet info, balance, and receive address
  btc/wallets/:name/addresses     - List/generate addresses
  btc/wallets/:name/utxos         - List all UTXOs
  btc/wallets/:name/qr            - QR code for receive address
  btc/wallets/:name/send          - Send bitcoin
  btc/wallets/:name/estimate      - Estimate send fee
  btc/wallets/:name/consolidate   - Consolidate UTXOs
  btc/wallets/:name/compact       - Remove spent empty address records
  btc/wallets/:name/scan          - Scan retired addresses for errant funds
  btc/wallets/:name/psbt/*        - PSBT operations
`
