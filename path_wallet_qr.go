package btc

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/skip2/go-qrcode"
)

func pathWalletQR(b *btcBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "wallets/" + framework.GenericNameRegex("name") + "/qr",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "btc",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the wallet",
					Required:    true,
				},
				"size": {
					Type:        framework.TypeInt,
					Description: "QR code size in pixels (default: 256)",
					Default:     256,
				},
				"format": {
					Type:        framework.TypeString,
					Description: "Output format: 'png' (base64) or 'ascii' (default: png)",
					Default:     "png",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathWalletQRRead,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "qr",
					},
				},
			},
			HelpSynopsis:    pathWalletQRHelpSynopsis,
			HelpDescription: pathWalletQRHelpDescription,
		},
	}
}

func (b *btcBackend) pathWalletQRRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	size := data.Get("size").(int)
	format := data.Get("format").(string)

	b.Logger().Debug("QR code request", "wallet", name, "format", format, "size", size)

	if size < 64 || size > 1024 {
		return logical.ErrorResponse("size must be between 64 and 1024"), nil
	}

	w, err := getWallet(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if w == nil {
		return logical.ErrorResponse("wallet %q not found", name), nil
	}

	// Get Electrum client to find unused address
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Electrum server: %w", err)
	}

	// Get stored addresses
	addresses, err := getStoredAddresses(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	// Track if we need to reconnect (stale connection detected)
	reconnectAttempted := false

	// Find unused address (must already exist - reads don't generate new addresses)
	var receiveAddress string
	for _, addr := range addresses {
		if addr.Spent {
			continue
		}
		history, err := client.GetHistory(addr.ScriptHash)
		if err != nil {
			// Try reconnect if needed
			if !reconnectAttempted && b.handleClientError(err) {
				reconnectAttempted = true
				if newClient, reconErr := b.getClient(ctx, req.Storage); reconErr == nil {
					client = newClient
					history, err = client.GetHistory(addr.ScriptHash)
				}
			}
		}
		if err == nil && len(history) == 0 {
			receiveAddress = addr.Address
			break
		}
	}

	// Return error if no unused address available
	if receiveAddress == "" {
		return logical.ErrorResponse("no unused address available - generate one with: vault write btc/wallets/%s/addresses", name), nil
	}

	// Generate BIP21 URI
	uri := fmt.Sprintf("bitcoin:%s", receiveAddress)

	respData := map[string]interface{}{
		"address": receiveAddress,
		"uri":     uri,
	}

	if format == "ascii" {
		// Generate ASCII QR code
		qr, err := qrcode.New(uri, qrcode.Medium)
		if err != nil {
			return nil, fmt.Errorf("failed to generate QR code: %w", err)
		}
		respData["qr"] = qr.ToSmallString(false)
		respData["display_hint"] = "vault read -field=qr btc/wallets/" + name + "/qr format=ascii"
	} else {
		// Generate PNG as base64
		png, err := qrcode.Encode(uri, qrcode.Medium, size)
		if err != nil {
			return nil, fmt.Errorf("failed to generate QR code: %w", err)
		}
		respData["qr_png"] = base64.StdEncoding.EncodeToString(png)
	}

	return &logical.Response{Data: respData}, nil
}

const pathWalletQRHelpSynopsis = `
Get a QR code for the wallet's receive address.
`

const pathWalletQRHelpDescription = `
This endpoint returns a QR code for the wallet's current receive address.
The QR code contains a BIP21 URI (bitcoin:address).

Example:
  $ vault read btc/wallets/my-wallet/qr
  $ vault read btc/wallets/my-wallet/qr size=512

For ASCII format, use -field to display correctly in terminal:
  $ vault read -field=qr btc/wallets/my-wallet/qr format=ascii

Parameters:
  - size: QR code size in pixels (default: 256, range: 64-1024)
  - format: 'png' for base64-encoded PNG, 'ascii' for terminal display

Response:
  - address: The receive address
  - uri: BIP21 URI (bitcoin:address)
  - qr_png: Base64-encoded PNG (if format=png)
  - qr: ASCII art QR code (if format=ascii)
  - display_hint: Command to display ASCII QR properly (if format=ascii)
`
