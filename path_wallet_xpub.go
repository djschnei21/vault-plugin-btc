package btc

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/djschnei21/vault-plugin-btc/wallet"
)

func pathWalletXpub(b *btcBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "wallets/" + framework.GenericNameRegex("name") + "/xpub",
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
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathWalletXpubRead,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "xpub",
					},
				},
			},
			HelpSynopsis:    pathWalletXpubHelpSynopsis,
			HelpDescription: pathWalletXpubHelpDescription,
		},
	}
}

func (b *btcBackend) pathWalletXpubRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	b.Logger().Debug("reading wallet xpub", "wallet", name)

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

	// Get the extended public key
	xpub, derivationPath, err := wallet.GetAccountXpub(w.Seed, network, w.AddressType)
	if err != nil {
		return nil, fmt.Errorf("failed to derive xpub: %w", err)
	}

	// Determine the key format name based on address type and network
	var keyFormat string
	switch w.AddressType {
	case AddressTypeP2WPKH:
		if network == "mainnet" {
			keyFormat = "zpub"
		} else {
			keyFormat = "vpub"
		}
	case AddressTypeP2TR:
		if network == "mainnet" {
			keyFormat = "xpub"
		} else {
			keyFormat = "tpub"
		}
	default:
		keyFormat = "xpub"
	}

	// Build output descriptor for Sparrow/other wallets
	var descriptor string
	switch w.AddressType {
	case AddressTypeP2WPKH:
		descriptor = fmt.Sprintf("wpkh([fingerprint%s]%s/<0;1>/*)", derivationPath[1:], xpub)
	case AddressTypeP2TR:
		descriptor = fmt.Sprintf("tr([fingerprint%s]%s/<0;1>/*)", derivationPath[1:], xpub)
	}

	b.Logger().Debug("xpub read complete", "wallet", name, "format", keyFormat)

	return &logical.Response{
		Data: map[string]interface{}{
			"xpub":            xpub,
			"format":         keyFormat,
			"derivation_path": derivationPath,
			"address_type":   w.AddressType,
			"network":        network,
			"descriptor":     descriptor,
		},
	}, nil
}

const pathWalletXpubHelpSynopsis = `
Export the wallet's extended public key (xpub/zpub) for watch-only wallet setup.
`

const pathWalletXpubHelpDescription = `
This endpoint exports the account-level extended public key for use in external
wallet software like Sparrow. This enables a watch-only wallet workflow:

1. Export the xpub from Vault
2. Import it into Sparrow (or similar) as a watch-only wallet
3. Use Sparrow to construct PSBTs (Partially Signed Bitcoin Transactions)
4. Bring the PSBT back to Vault for signing via the /psbt/sign endpoint

Key Formats:
  - p2wpkh wallets: zpub (mainnet) or vpub (testnet) per SLIP-0132
  - p2tr wallets: xpub (mainnet) or tpub (testnet) - no SLIP-0132 standard

Response fields:
  - xpub: The extended public key string
  - format: Key format name (zpub, vpub, xpub, tpub)
  - derivation_path: BIP84/86 derivation path (e.g., m/84'/0'/0')
  - address_type: Wallet address type (p2wpkh or p2tr)
  - network: Bitcoin network (mainnet, testnet4, signet)
  - descriptor: Output descriptor template for wallet import

Example:
  $ vault read btc/wallets/my-wallet/xpub

Importing into Sparrow:
  1. File > New Wallet > "Watch Only"
  2. Paste the xpub value
  3. Sparrow will recognize the format and derive addresses

Security Note:
  The xpub allows deriving all public keys and addresses but CANNOT spend funds.
  It's safe to share with watch-only wallet software, but treat it as sensitive
  since it reveals your complete transaction history and balance.
`
