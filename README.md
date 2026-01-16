# Vault Plugin: Bitcoin Secrets Engine

A HashiCorp Vault secrets engine plugin for Bitcoin custodial operations. Each wallet is an HD wallet with secure key storage, automatic address management, and PSBT support for complex transactions.

## Features

- **HD Wallet Management** - BIP84/BIP86 hierarchical deterministic wallets with secure seed storage
- **Taproot Support** - Default `bc1p...` (P2TR) addresses with Schnorr signatures, or legacy `bc1q...` (P2WPKH)
- **Automatic Address Reuse Prevention** - Tracks spent addresses and prevents receiving to previously-used addresses
- **Simple Send/Receive** - Streamlined API for common custodial operations
- **Watch-Only Wallet Coordination** - Export xpubs for use with Sparrow, Caravan, or other wallet software
- **PSBT Signing** - Sign PSBTs created by external wallets for complex transactions
- **Multi-Sig Support** - Participate as one signer in multi-sig setups with external coordinators
- **Fee Estimation** - Preview transaction fees before sending
- **UTXO Management** - List, consolidate, and manage UTXOs with privacy warnings
- **Multi-Network Support** - Mainnet, Testnet4, and custom Signet configurations
- **Automatic Reconnection** - Recovers gracefully from stale Electrum connections

## Quick Start

```bash
# Build the plugin
make build

# Start Vault in dev mode (terminal 1)
make dev

# In another terminal, enable the plugin
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'
make enable
```

### Configure for Testnet4 (Recommended for Testing)

```bash
# Configure for testnet4 (uses random server from pool)
vault write btc/config network=testnet4

# Create a wallet (Taproot by default, 5 addresses pre-generated)
vault write btc/wallets/test description="Test wallet"

# Get receive address, fund it from a faucet
vault read btc/wallets/test

# Check balance after funding
vault read btc/wallets/test
```

### Configure for Mainnet

```bash
# Configure for mainnet (uses random server from pool)
vault write btc/config network=mainnet

# Create a wallet
vault write btc/wallets/treasury description="Main treasury"

# For SegWit addresses instead of Taproot
vault write btc/wallets/legacy address_type=p2wpkh

# Get wallet info, balance, and receive address
vault read btc/wallets/treasury

# Send bitcoin
vault write btc/wallets/treasury/send to="bc1p..." amount=50000
```

### Electrum Server Pools

Servers are randomly selected from the pool per connection. To use a specific server:

```bash
vault write btc/config network=mainnet electrum_url="ssl://electrum.blockstream.info:50002"
```

| Network | Servers in Pool |
|---------|-----------------|
| Mainnet | `electrum.blockstream.info:50002`, `electrum.bitaroo.net:50002`, `electrum.emzy.de:50002` |
| Testnet4 | `mempool.space:40002`, `electrum.blockstream.info:60002` |
| Signet | (no default - requires explicit `electrum_url`) |

> **Note:** For production use, consider running your own Electrum server for privacy and reliability.

## Installation

### Prerequisites

- Go 1.21 or later
- HashiCorp Vault 1.15 or later

### Building from Source

```bash
git clone https://github.com/djschnei21/vault-plugin-btc.git
cd vault-plugin-btc
make build
```

### Registering with Vault

```bash
SHA256=$(sha256sum vault/plugins/vault-plugin-btc | cut -d' ' -f1)
vault plugin register -sha256=$SHA256 secret vault-plugin-btc
vault secrets enable -path=btc vault-plugin-btc
```

## Configuration

Configure the secrets engine with a network. Electrum server is optional - if not specified, a random server from the default pool is used per connection:

```bash
# Use random server from pool (recommended)
vault write btc/config network=testnet4

# Or specify a server explicitly
vault write btc/config \
    network=mainnet \
    electrum_url="ssl://electrum.blockstream.info:50002" \
    min_confirmations=1
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `network` | `mainnet` | Bitcoin network (`mainnet`, `testnet4`, or `signet`) |
| `electrum_url` | (random from pool) | Electrum server URL. If not set, uses random server from pool. |
| `min_confirmations` | `1` | Minimum confirmations required to spend UTXOs |

### Default Electrum Server Pools

Random server selection provides load balancing and resilience. A new server is selected each time a connection is established.

| Network | Server Pool |
|---------|-------------|
| Mainnet | `electrum.blockstream.info`, `electrum.bitaroo.net`, `electrum.emzy.de` |
| Testnet4 | `mempool.space`, `electrum.blockstream.info` |
| Signet | (no default pool - requires explicit `electrum_url`) |

To see the current pool:
```bash
vault read btc/config
```

## API Reference

### Wallets

#### List Wallets
```
LIST btc/wallets
```

#### Create Wallet
```
POST btc/wallets/:name
```

**Parameters:**
- `description` (string) - Optional description
- `address_type` (string) - Address type: `p2tr` (Taproot, default) or `p2wpkh` (SegWit)

Creates a new wallet with 5 pre-generated addresses.

**Response:**
```json
{
  "name": "treasury",
  "network": "mainnet",
  "address_type": "p2tr",
  "confirmed": 0,
  "unconfirmed": 0,
  "total": 0,
  "address_count": 5,
  "receive_address": "bc1p...",
  "receive_index": 0,
  "created_at": "2024-01-15T10:30:00Z"
}
```

#### Get Wallet
```
GET btc/wallets/:name
```

Returns wallet info, balance, and a receive address. The receive address is the first unused address from the pre-generated pool. If all addresses have been used, `receive_address` will be `null` with a warning to generate more via `POST btc/wallets/:name/addresses`.

**Response:**
```json
{
  "name": "treasury",
  "network": "mainnet",
  "address_type": "p2tr",
  "confirmed": 150000,
  "unconfirmed": 0,
  "total": 150000,
  "address_count": 5,
  "receive_address": "bc1p...",
  "receive_index": 2,
  "created_at": "2024-01-15T10:30:00Z"
}
```

If no unused addresses are available:
```json
{
  "receive_address": null,
  "warning": "no unused address available - generate one with: vault write btc/wallets/treasury/addresses"
}
```

All amounts are in satoshis (1 BTC = 100,000,000 satoshis).

#### Delete Wallet
```
DELETE btc/wallets/:name
```

> **Warning:** Deleting a wallet permanently destroys the seed. Ensure all funds are transferred first.

#### Export Extended Public Key (xpub)
```
GET btc/wallets/:name/xpub
```

Exports the account-level extended public key for watch-only wallet setup in external software like Sparrow.

**Response:**
```json
{
  "xpub": "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
  "format": "zpub",
  "derivation_path": "m/84'/0'/0'",
  "address_type": "p2wpkh",
  "network": "mainnet",
  "descriptor": "wpkh([fingerprint/84'/0'/0']zpub.../&lt;0;1&gt;/*)"
}
```

**Key formats by wallet type:**
- `p2wpkh` mainnet: `zpub` (SLIP-0132)
- `p2wpkh` testnet: `vpub` (SLIP-0132)
- `p2tr` mainnet: `xpub` (standard)
- `p2tr` testnet: `tpub` (standard)

**Watch-only wallet workflow:**
1. Export the xpub: `vault read btc/wallets/my-wallet/xpub`
2. Import into Sparrow as a watch-only wallet
3. Use Sparrow to construct PSBTs
4. Sign the PSBT via Vault: `vault write btc/wallets/my-wallet/psbt/sign psbt="..."`
5. Broadcast the signed transaction

> **Security Note:** The xpub allows deriving all addresses but cannot spend funds. Treat it as sensitive since it reveals your complete transaction history.

---

### Addresses

#### List Addresses
```
GET btc/wallets/:name/addresses
```

Returns all generated addresses for the wallet.

**Response:**
```json
{
  "wallet": "treasury",
  "addresses": [
    {
      "address": "bc1p...",
      "index": 0,
      "derivation_path": "m/86'/0'/0'/0/0",
      "spent": false
    }
  ],
  "count": 1
}
```

#### Generate Addresses
```
POST btc/wallets/:name/addresses
```

Generate one or more unused addresses.

**Parameters:**
- `count` (int) - Number of addresses to return (default: 1, max: 100)

**Response:**
```json
{
  "wallet": "treasury",
  "addresses": [
    {
      "address": "bc1p...",
      "index": 1,
      "derivation_path": "m/86'/0'/0'/0/1"
    }
  ],
  "count": 1,
  "generated": 1
}
```

---

### UTXOs

List all unspent transaction outputs for a wallet.

```
GET btc/wallets/:name/utxos
```

**Parameters:**
- `min_confirmations` (int) - Override config min_confirmations

**Response:**
```json
{
  "wallet": "treasury",
  "utxos": [
    {
      "txid": "abc123...",
      "vout": 0,
      "value": 100000,
      "address": "bc1p...",
      "address_index": 0,
      "confirmations": 6
    }
  ],
  "count": 1,
  "total_value": 100000
}
```

---

### Consolidate

Consolidate multiple UTXOs into a single UTXO. Useful for reducing future transaction fees and cleaning up dust.

```
POST btc/wallets/:name/consolidate
```

**Parameters:**
- `fee_rate` (int) - Fee rate in sat/vbyte (default: 10)
- `min_confirmations` (int) - Override config min_confirmations
- `below_value` (int) - Only consolidate UTXOs below this value in satoshis (default: 0 = all)
- `dry_run` (bool) - Preview without broadcasting (default: false)
- `compact` (bool) - Run compaction after consolidation (default: false)

**Response:**
```json
{
  "txid": "def456...",
  "inputs_consolidated": 5,
  "total_input": 50000,
  "fee": 2900,
  "output_value": 47100,
  "output_address": "bc1p...",
  "broadcast": true,
  "privacy_warning": "Consolidation links all input addresses together, revealing common ownership"
}
```

> **Privacy Warning:** Consolidation links all input addresses together via the common-input-ownership heuristic, revealing they are controlled by the same entity. Only consolidate when privacy implications are acceptable.

---

### Compact

Remove stored address records for addresses that are fully spent and empty. Since addresses can be regenerated from the wallet seed, there's no need to store records for addresses that will never be used again.

```
POST btc/wallets/:name/compact
```

**Response:**
```json
{
  "previous_first_active": 0,
  "new_first_active": 5,
  "addresses_deleted": 5,
  "addresses_remaining": 3
}
```

---

### Scan

Scan for funds on retired or untracked addresses. Two scan modes are available:

- **Retired scan**: Check addresses below FirstActiveIndex that were compacted away
- **Gap scan**: Check addresses beyond NextAddressIndex for deposits to untracked addresses

```
GET/POST btc/wallets/:name/scan
```

**Parameters:**
- `retired` (bool) - Scan retired addresses below FirstActiveIndex (default: true)
- `gap` (int) - Scan N addresses beyond NextAddressIndex (default: 0)
- `sweep` (bool) - Move found retired funds to a fresh address (default: false)
- `fee_rate` (int) - Fee rate for sweep transaction in sat/vbyte (default: 10)

**Examples:**
```bash
# Scan retired addresses only
vault read btc/wallets/my-wallet/scan

# Scan 20 addresses ahead for untracked deposits
vault read btc/wallets/my-wallet/scan gap=20

# Scan both retired and ahead
vault read btc/wallets/my-wallet/scan retired=true gap=20

# Sweep found retired funds
vault write btc/wallets/my-wallet/scan sweep=true
```

**Response (gap scan with found funds):**
```json
{
  "gap_scanned": 20,
  "gap_found": [
    {
      "address": "bc1p...",
      "index": 50,
      "confirmed": 10000,
      "unconfirmed": 0,
      "total": 10000
    }
  ],
  "gap_total": 10000,
  "gap_registered": [{"address": "bc1p...", "index": 50}],
  "new_next_index": 51,
  "total_found": 10000,
  "message": "found: 10000 sats on 1 untracked (now registered)"
}
```

Gap scan automatically registers found addresses and updates NextAddressIndex - no sweep needed. Funds stay in place.

**Response (retired scan with sweep):**
```json
{
  "retired_scanned": 5,
  "retired_found": [...],
  "retired_total": 10000,
  "sweep_txid": "abc123...",
  "sweep_address": "bc1p...",
  "sweep_fee": 1540,
  "sweep_output": 8460,
  "sweep_broadcast": true,
  "total_found": 10000
}
```

---

### QR Code

Get a QR code for the wallet's receive address.

```
GET btc/wallets/:name/qr
```

**Parameters:**
- `size` (int) - QR code size in pixels (default: 256, range: 64-1024)
- `format` (string) - `png` for base64 PNG, `ascii` for terminal display

**Response (format=png):**
```json
{
  "address": "bc1q...",
  "uri": "bitcoin:bc1q...",
  "qr_png": "iVBORw0KGgoAAAANSUhEUgAA..."
}
```

**Response (format=ascii):**
```json
{
  "address": "bc1q...",
  "uri": "bitcoin:bc1q...",
  "qr": "█████████████████████████████\n█████..."
}
```

---

### Send

Send bitcoin from a wallet.

```
POST btc/wallets/:name/send
```

**Parameters:**
- `to` (string, required) - Destination Bitcoin address
- `amount` (int, required) - Amount in satoshis
- `fee_rate` (int) - Fee rate in sat/vbyte (default: 10)
- `min_confirmations` (int) - Override config min_confirmations

**Response:**
```json
{
  "txid": "abc123...",
  "fee": 1410,
  "amount": 50000,
  "to": "bc1q...",
  "change_amount": 98590,
  "change_address": "bc1q...",
  "broadcast": true
}
```

---

### Fee Estimation

Estimate the fee for a potential send without broadcasting.

```
POST btc/wallets/:name/estimate
```

**Parameters:**
- `to` (string, required) - Destination Bitcoin address
- `amount` (int, required) - Amount in satoshis
- `fee_rate` (int) - Fee rate in sat/vbyte (default: 10)

**Response:**
```json
{
  "amount": 50000,
  "to": "bc1q...",
  "fee_rate": 10,
  "estimated_fee": 1410,
  "estimated_vsize": 141,
  "change_amount": 98590,
  "inputs_used": 1,
  "total_available": 150000,
  "sufficient": true
}
```

---

### PSBT Operations

PSBTs (Partially Signed Bitcoin Transactions) enable watch-only wallet workflows and multi-sig setups. Create PSBTs in external software (Sparrow, Caravan) and sign them with Vault.

#### Sign PSBT

```
POST btc/wallets/:name/psbt/sign
```

**Parameters:**
- `psbt` (string, required) - Base64-encoded PSBT

**Response:**
```json
{
  "psbt": "cHNidP8BAH0CAA...",
  "inputs_total": 1,
  "inputs_signed": 1
}
```

#### Finalize and Broadcast PSBT

```
POST btc/wallets/:name/psbt/finalize
```

**Parameters:**
- `psbt` (string, required) - Base64-encoded signed PSBT
- `broadcast` (bool) - Whether to broadcast (default: true)

**Response:**
```json
{
  "txid": "abc123...",
  "hex": "0200000001...",
  "broadcast": true,
  "broadcast_txid": "abc123..."
}
```

---

### Multi-Sig Support

Vault can participate as one signer in a multi-sig (m-of-n) setup. The recommended workflow uses Vault as a signing device while an external coordinator (Sparrow, Caravan, Nunchuk) manages the multi-sig wallet.

#### Setup (One-Time)

```bash
# 1. Export xpub from Vault
vault read btc/wallets/treasury/xpub
# Returns: zpub6rFR7y4Q2AijBE... (for p2wpkh wallet)

# 2. Export xpubs from other signers (Coldcard, Ledger, etc.)
# 3. Import all xpubs into coordinator (Sparrow) to create multi-sig wallet
# 4. Sparrow generates the multi-sig descriptor and addresses
```

#### Spending from Multi-Sig

```bash
# 1. Create PSBT in Sparrow (or other coordinator)
# 2. Export PSBT and sign with Vault
vault write btc/wallets/treasury/psbt/sign psbt="cHNidP8BAH..."
# Response shows inputs_signed: 1 (Vault's signature added)

# 3. Sign with other signers (Coldcard, Ledger, etc.)
# 4. Once threshold met (e.g., 2-of-3), finalize in Sparrow or Vault:
vault write btc/wallets/treasury/psbt/finalize psbt="cHNidP8..." broadcast=true
```

#### Supported Multi-Sig Types

| Type | Script | Notes |
|------|--------|-------|
| P2WSH | Native SegWit multi-sig | Most common, lower fees |
| P2SH-P2WSH | Wrapped SegWit | Legacy compatibility |

The `/psbt/sign` endpoint automatically detects multi-sig inputs by:
1. Matching BIP32 derivation paths in the PSBT
2. Scanning witness scripts for pubkeys derived from the wallet

#### Example: 2-of-3 Multi-Sig with Vault

```
Signer 1: Vault (zpub from vault read btc/wallets/treasury/xpub)
Signer 2: Coldcard hardware wallet
Signer 3: Ledger hardware wallet

Coordinator: Sparrow (manages addresses, creates PSBTs)

Spending requires any 2 of 3 signatures.
```

---

## Usage Examples

### Basic Workflow

```bash
# Configure for testnet4
vault write btc/config network=testnet4

# Create a wallet
vault write btc/wallets/test description="Test wallet"

# Get wallet info (includes receive_address)
vault read btc/wallets/test

# Estimate a send
vault write btc/wallets/test/estimate \
    to="tb1q..." \
    amount=10000 \
    fee_rate=5

# Send bitcoin
vault write btc/wallets/test/send \
    to="tb1q..." \
    amount=10000 \
    fee_rate=5
```

### Watch-Only Wallet Workflow

For complex transactions (multi-output, custom fee control, coin selection), use an external wallet like Sparrow:

```bash
# 1. Export xpub from Vault
vault read btc/wallets/treasury/xpub

# 2. Import xpub into Sparrow as watch-only wallet
# 3. Create transaction in Sparrow (multi-output, custom fees, etc.)
# 4. Export PSBT from Sparrow

# 5. Sign the PSBT with Vault
vault write btc/wallets/treasury/psbt/sign \
    psbt="cHNidP8..."

# 6. Finalize and broadcast
vault write btc/wallets/treasury/psbt/finalize \
    psbt="cHNidP8..." \
    broadcast=true
```

### Vault Policies

Read-only policy:
```hcl
path "btc/wallets" {
  capabilities = ["list"]
}

path "btc/wallets/*" {
  capabilities = ["read"]
}
```

Full access policy:
```hcl
path "btc/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
```

## Architecture

### Key Derivation

The plugin supports two address types with different BIP derivation paths:

**BIP86 - Taproot (P2TR)** - Default for new wallets
```
m / 86' / coin_type' / account' / change / address_index
```

**BIP84 - Native SegWit (P2WPKH)**
```
m / 84' / coin_type' / account' / change / address_index
```

| Component | Value | Description |
|-----------|-------|-------------|
| Purpose | 86' or 84' | Taproot or Native SegWit |
| Coin Type | 0' or 1' | Mainnet or Testnet4/Signet |
| Account | 0' | Single account per wallet |
| Change | 0 or 1 | External (receiving) or Internal (change) |
| Address Index | 0+ | Sequential index |

### Address Types

| Type | Prefix | BIP | Example |
|------|--------|-----|---------|
| P2TR (Taproot) | `bc1p` / `tb1p` | BIP86 | `bc1p5d7rjq7g6rd...` |
| P2WPKH (SegWit) | `bc1q` / `tb1q` | BIP84 | `bc1qcr8te4kr609...` |

Taproot addresses use Schnorr signatures and offer:
- Improved privacy (key-path spends look identical)
- Slightly smaller transactions
- Future script flexibility

### Address Reuse Prevention

The plugin automatically prevents address reuse:

1. **Initial Pool**: Wallet creation generates 5 addresses upfront
2. **Spent Tracking**: Addresses used as transaction inputs are marked as spent
3. **History Check**: Addresses with any transaction history are not reused for receiving
4. **Explicit Generation**: Use `POST btc/wallets/:name/addresses` to generate more addresses when needed

Reading a wallet returns `receive_address` - the first unused address from the pool. If all addresses have been used, it returns `null` with a hint to generate more. This follows REST conventions where read operations never cause writes.

### Storage

| Path | Contents | Encryption |
|------|----------|------------|
| `config` | Electrum URL, network, settings | Seal-wrapped |
| `wallets/:name` | Seed, address index, metadata | Seal-wrapped |
| `addresses/:wallet/:index` | Address, scripthash, path | Standard |

## Security

- **Seed Encryption**: Seeds are stored with Vault's seal-wrap encryption
- **No Key Export**: Private keys and seeds cannot be exported via API
- **TLS Communication**: All Electrum connections use TLS
- **Address Reuse Prevention**: Automatic address lifecycle management

## Development

### Project Structure

```
vault-plugin-btc/
├── cmd/vault-plugin-btc/main.go
├── backend.go              # Backend factory, client management
├── cache.go                # Address/balance caching
├── path_config.go          # Configuration endpoint
├── path_wallets.go         # Wallet CRUD, balance, receive address
├── path_wallet_addresses.go # Address listing and generation
├── path_wallet_utxos.go    # UTXO listing
├── path_wallet_qr.go       # QR code generation
├── path_wallet_send.go     # Send and fee estimation
├── path_wallet_psbt.go     # PSBT operations
├── path_wallet_consolidate.go # UTXO consolidation
├── path_wallet_compact.go  # Address record cleanup
├── path_wallet_scan.go     # Retired address scanning
├── address_storage.go      # Address persistence
├── utxo.go                 # UTXO fetching helpers
├── electrum/client.go      # Electrum protocol client
├── wallet/
│   ├── keys.go             # HD key derivation (BIP84/BIP86)
│   ├── address.go          # Address generation (P2WPKH/P2TR)
│   └── transaction.go      # Transaction building and signing
└── Makefile
```

### Building

```bash
make build    # Build the plugin
make test     # Run tests
make dev      # Start Vault in dev mode
make enable   # Enable the plugin
```

## License

MIT License
