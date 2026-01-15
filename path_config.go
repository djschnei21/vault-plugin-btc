package btc

import (
	"context"
	cryptorand "crypto/rand"
	"fmt"
	"math/big"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const configStoragePath = "config"

// Default Electrum server pools per network
// When no custom electrum_url is configured, a random server is selected per connection
var (
	MainnetElectrumServers = []string{
		"ssl://electrum.blockstream.info:50002",
		"ssl://electrum.bitaroo.net:50002",
		"ssl://electrum.emzy.de:50002",
	}

	Testnet4ElectrumServers = []string{
		"ssl://mempool.space:40002",
		"ssl://electrum.blockstream.info:60002",
	}

	// Signet has no default servers - requires explicit configuration
	SignetElectrumServers = []string{}
)

// getRandomServer returns a random server from the list for the given network
// Uses crypto/rand for secure randomness
func getRandomServer(network string) string {
	var servers []string
	switch network {
	case "mainnet":
		servers = MainnetElectrumServers
	case "testnet4":
		servers = Testnet4ElectrumServers
	case "signet":
		servers = SignetElectrumServers
	default:
		servers = MainnetElectrumServers
	}

	if len(servers) == 0 {
		return ""
	}

	// Use crypto/rand for secure random selection
	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(len(servers))))
	if err != nil {
		// Fallback to first server if crypto/rand fails (shouldn't happen)
		return servers[0]
	}

	return servers[n.Int64()]
}

// btcConfig stores the secrets engine configuration
type btcConfig struct {
	ElectrumURL      string `json:"electrum_url"`
	Network          string `json:"network"`
	MinConfirmations int    `json:"min_confirmations"`
}

func pathConfig(b *btcBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "config",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "btc",
			},
			Fields: map[string]*framework.FieldSchema{
				"electrum_url": {
					Type:        framework.TypeString,
					Description: "Electrum server URL. If not set, a random server from the default pool is used per connection.",
				},
				"network": {
					Type:        framework.TypeString,
					Description: "Bitcoin network: mainnet, testnet4, or signet (signet requires custom electrum_url)",
					Default:     "mainnet",
				},
				"min_confirmations": {
					Type:        framework.TypeInt,
					Description: "Minimum confirmations required to spend UTXOs (default: 1)",
					Default:     1,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathConfigRead,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "config",
					},
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathConfigWrite,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "config",
					},
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathConfigWrite,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "config",
					},
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathConfigDelete,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "config",
					},
				},
			},
			ExistenceCheck:  b.pathConfigExistenceCheck,
			HelpSynopsis:    pathConfigHelpSynopsis,
			HelpDescription: pathConfigHelpDescription,
		},
	}
}

func (b *btcBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, configStoragePath)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}
	return out != nil, nil
}

func (b *btcBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("reading config")
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		b.Logger().Debug("no config found")
		return nil, nil
	}

	b.Logger().Debug("config read", "network", config.Network, "electrum_url", config.ElectrumURL, "min_confirmations", config.MinConfirmations)

	respData := map[string]interface{}{
		"network":           config.Network,
		"min_confirmations": config.MinConfirmations,
	}

	if config.ElectrumURL != "" {
		respData["electrum_url"] = config.ElectrumURL
	} else {
		// Show the server pool for this network
		var servers []string
		switch config.Network {
		case "mainnet":
			servers = MainnetElectrumServers
		case "testnet4":
			servers = Testnet4ElectrumServers
		case "signet":
			servers = SignetElectrumServers
		}
		respData["electrum_url"] = "(random from pool)"
		respData["electrum_pool"] = servers
	}

	return &logical.Response{Data: respData}, nil
}

func (b *btcBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("writing config", "operation", req.Operation)
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	createOperation := req.Operation == logical.CreateOperation

	if config == nil {
		if !createOperation {
			return nil, fmt.Errorf("config not found during update operation")
		}
		b.Logger().Debug("creating new config")
		config = &btcConfig{}
	}

	if electrumURL, ok := data.GetOk("electrum_url"); ok {
		config.ElectrumURL = electrumURL.(string)
	}
	// If not provided, leave empty to use random server selection

	if network, ok := data.GetOk("network"); ok {
		config.Network = network.(string)
	} else if createOperation {
		config.Network = data.Get("network").(string)
	}

	if minConf, ok := data.GetOk("min_confirmations"); ok {
		config.MinConfirmations = minConf.(int)
	} else if createOperation {
		config.MinConfirmations = data.Get("min_confirmations").(int)
	}

	// Validate network
	if config.Network != "mainnet" && config.Network != "testnet4" && config.Network != "signet" {
		return logical.ErrorResponse("network must be 'mainnet', 'testnet4', or 'signet'"), nil
	}

	// Validate min_confirmations
	if config.MinConfirmations < 0 {
		return logical.ErrorResponse("min_confirmations must be >= 0"), nil
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// Reset the client so the new config takes effect
	b.reset()

	b.Logger().Info("config saved", "network", config.Network, "electrum_url", config.ElectrumURL, "min_confirmations", config.MinConfirmations)
	return nil, nil
}

func (b *btcBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("deleting config")
	err := req.Storage.Delete(ctx, configStoragePath)
	if err != nil {
		return nil, fmt.Errorf("error deleting config: %w", err)
	}

	b.reset()

	b.Logger().Info("config deleted")
	return nil, nil
}

// getConfig retrieves the configuration from storage
func getConfig(ctx context.Context, s logical.Storage) (*btcConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, fmt.Errorf("error retrieving config: %w", err)
	}

	if entry == nil {
		return nil, nil
	}

	config := new(btcConfig)
	if err := entry.DecodeJSON(config); err != nil {
		return nil, fmt.Errorf("error decoding config: %w", err)
	}

	return config, nil
}

// getNetwork retrieves the network from config, defaulting to mainnet
func getNetwork(ctx context.Context, s logical.Storage) (string, error) {
	config, err := getConfig(ctx, s)
	if err != nil {
		return "", err
	}

	if config == nil || config.Network == "" {
		return "mainnet", nil
	}

	return config.Network, nil
}

// getMinConfirmations retrieves the min_confirmations from config, defaulting to 1
func getMinConfirmations(ctx context.Context, s logical.Storage) (int, error) {
	config, err := getConfig(ctx, s)
	if err != nil {
		return 0, err
	}

	if config == nil {
		return 1, nil // Default to 1 confirmation
	}

	// If not set (zero value), return default of 1
	if config.MinConfirmations == 0 {
		return 1, nil
	}

	return config.MinConfirmations, nil
}

const pathConfigHelpSynopsis = `
Configure the Bitcoin secrets engine.
`

const pathConfigHelpDescription = `
This endpoint configures the Bitcoin secrets engine with network, Electrum
server, and confirmation requirements.

Parameters:
  - network: mainnet, testnet4, or signet (default: mainnet)
  - electrum_url: Electrum server URL (optional - uses random server from pool if not set)
  - min_confirmations: Minimum confirmations to spend UTXOs (default: 1)

Server Selection:
  If electrum_url is not specified, a random server from the default pool is
  selected each time a new connection is established. This provides load
  balancing and resilience if one server is unavailable.

Example (testnet4 with random server selection):
  $ vault write btc/config network=testnet4

Example (mainnet with specific server):
  $ vault write btc/config \
      network=mainnet \
      electrum_url="ssl://electrum.blockstream.info:50002"

Example (custom signet - requires explicit server):
  $ vault write btc/config \
      network=signet \
      electrum_url="ssl://your-signet-electrum:50002"

Default server pools:
  - mainnet:  electrum.blockstream.info, electrum.bitaroo.net, electrum.emzy.de
  - testnet4: mempool.space, electrum.blockstream.info
  - signet:   (no default pool - requires explicit electrum_url)

To see which servers are in the pool:
  $ vault read btc/config
`
