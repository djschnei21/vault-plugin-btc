# Vault Plugin: Bitcoin Secrets Engine

[![Go Report Card](https://goreportcard.com/badge/github.com/djschnei21/vault-plugin-btc)](https://goreportcard.com/report/github.com/djschnei21/vault-plugin-btc)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

https://github.com/djschnei21/vault-plugin-btc

A HashiCorp Vault secrets engine plugin for Bitcoin custodial operations. Lightweight Electrum-based backend (no full node required), modern Taproot default, and built for secure signing workflows — from simple sends to multi-sig coordination with external wallets.

## Features

- **HD Wallet Management** - BIP84/BIP86 hierarchical deterministic wallets with secure seed storage
- **Taproot Support** - Default `bc1p...` (P2TR) addresses with Schnorr signatures, or `bc1q...` (P2WPKH)
- **Automatic Address Reuse Prevention** - Tracks spent addresses and prevents receiving to previously-used addresses
- **Simple Send/Receive** - Streamlined API for common custodial operations
- **Watch-Only Wallet Coordination** - Export xpubs for use with Sparrow, Caravan, or other wallet software
- **PSBT Signing** - Sign PSBTs created by external wallets for complex transactions
- **Multi-Sig Support** - Participate as one signer in multi-sig setups with external coordinators
- **Fee Estimation** - Preview transaction fees before sending
- **UTXO Management** - List, consolidate, and manage UTXOs with privacy warnings
- **Multi-Network Support** - Mainnet, Testnet4, and Signet
- **Automatic Reconnection** - Recovers gracefully from stale Electrum connections

## Quick Start

```bash
# Build and start Vault in dev mode (terminal 1)
make dev

# In another terminal, mount the plugin
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'
vault secrets enable -path=btc vault-plugin-btc
```

---

## API Reference

All amounts are in satoshis (1 BTC = 100,000,000 satoshis).

---

### Configuration

#### `btc/config`

| Operation | Description |
|-----------|-------------|
| READ | Get current configuration |
| CREATE/UPDATE | Set configuration |
| DELETE | Remove configuration |

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `network` | string | `mainnet` | Bitcoin network: `mainnet`, `testnet4`, or `signet` |
| `electrum_url` | string | _(pool)_ | Electrum server URL (e.g., `ssl://electrum.blockstream.info:50002`). If not set, a random server from the default pool is used per connection. |
| `min_confirmations` | int | `1` | Minimum confirmations required to spend UTXOs |

**Default Server Pools:**

| Network | Servers |
|---------|---------|
| mainnet | `ssl://electrum.blockstream.info:50002`, `ssl://electrum.bitaroo.net:50002`, `ssl://electrum.emzy.de:50002` |
| testnet4 | `ssl://mempool.space:40002`, `ssl://electrum.blockstream.info:60002` |
| signet | _(no default pool — requires explicit `electrum_url`)_ |

---

### Wallets

#### `btc/wallets` — LIST

Returns a list of all wallet names.

#### `btc/wallets/:name`

| Operation | Description |
|-----------|-------------|
| READ | Get wallet info, balance, and receive address |
| CREATE | Create new wallet with HD seed (generates 5 initial addresses) |
| UPDATE | Update wallet description |
| DELETE | Delete wallet and all associated addresses |

**Parameters (CREATE/UPDATE):**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `name` | string | _(required)_ | Wallet name |
| `description` | string | | Optional description |
| `address_type` | string | `p2tr` | Address type: `p2tr` (Taproot) or `p2wpkh` (Native SegWit) |

**Response Fields (READ):**

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Wallet name |
| `network` | string | Bitcoin network |
| `address_type` | string | `p2tr` or `p2wpkh` |
| `confirmed` | int | Confirmed balance in satoshis |
| `unconfirmed` | int | Unconfirmed balance in satoshis |
| `total` | int | Total balance (confirmed + unconfirmed) |
| `address_count` | int | Number of generated addresses |
| `receive_address` | string | Current unused receive address (null if none available) |
| `receive_index` | int | Derivation index of receive address |
| `created_at` | string | ISO 8601 timestamp |
| `description` | string | Wallet description (if set) |
| `warning` | string | Present if no unused address available |

---

### Addresses

#### `btc/wallets/:name/addresses`

| Operation | Description |
|-----------|-------------|
| READ | List all addresses with balances and status |
| CREATE/UPDATE | Generate unused addresses |

**Parameters (CREATE/UPDATE):**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `count` | int | `1` | Number of unused addresses to return (max: 100) |

**Response Fields (READ):**

| Field | Type | Description |
|-------|------|-------------|
| `addresses` | array | List of address objects |
| `address_count` | int | Total number of addresses |
| `used_count` | int | Addresses with transaction history |
| `unused_count` | int | Addresses without transaction history |
| `total_confirmed` | int | Sum of all confirmed balances |
| `total_unconfirmed` | int | Sum of all unconfirmed balances |
| `total` | int | Total wallet balance |

**Address Object Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `address` | string | Bitcoin address |
| `index` | int | Derivation index |
| `derivation_path` | string | Full BIP84/86 derivation path |
| `confirmed` | int | Confirmed balance |
| `unconfirmed` | int | Unconfirmed balance |
| `total` | int | Total balance |
| `tx_count` | int | Number of transactions |
| `used` | bool | Has transaction history |
| `spent` | bool | Was used as a transaction input |

---

### UTXOs

#### `btc/wallets/:name/utxos`

| Operation | Description |
|-----------|-------------|
| READ | List all unspent transaction outputs |

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `min_confirmations` | int | `0` | Filter UTXOs by minimum confirmations |

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `utxos` | array | List of UTXO objects (sorted by value, largest first) |
| `utxo_count` | int | Total number of UTXOs |
| `total_value` | int | Sum of all UTXO values |

**UTXO Object Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `txid` | string | Transaction ID |
| `vout` | int | Output index |
| `address` | string | Address owning this UTXO |
| `address_index` | int | Derivation index of address |
| `value` | int | Amount in satoshis |
| `height` | int | Block height (0 if unconfirmed) |
| `confirmations` | int | Number of confirmations |

---

### Send

#### `btc/wallets/:name/send`

| Operation | Description |
|-----------|-------------|
| CREATE/UPDATE | Create, sign, and broadcast a transaction |

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `to` | string | _(required)_ | Destination Bitcoin address |
| `amount` | int | _(required unless max_send)_ | Amount in satoshis |
| `fee_rate` | int | `10` | Fee rate in sat/vbyte |
| `min_confirmations` | int | _(from config)_ | Minimum UTXO confirmations |
| `dry_run` | bool | `false` | Estimate fee without broadcasting |
| `max_send` | bool | `false` | Send all available funds minus fee |

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `txid` | string | Transaction ID |
| `fee` | int | Fee paid in satoshis |
| `amount` | int | Amount sent |
| `to` | string | Destination address |
| `change_amount` | int | Change amount (not present if max_send) |
| `change_address` | string | Change address (not present if max_send) |
| `broadcast` | bool | Whether transaction was broadcast |
| `error` | string | Error message (if broadcast failed) |
| `hex` | string | Raw transaction hex (if broadcast failed) |

**Dry Run Response Fields (additional):**

| Field | Type | Description |
|-------|------|-------------|
| `dry_run` | bool | Always `true` |
| `estimated_fee` | int | Estimated fee in satoshis |
| `estimated_vsize` | int | Estimated transaction size in vbytes |
| `inputs_used` | int | Number of UTXOs that would be spent |
| `total_available` | int | Total available balance |
| `max_send` | bool | Whether max_send was requested |

---

### QR Code

#### `btc/wallets/:name/qr`

| Operation | Description |
|-----------|-------------|
| READ | Generate QR code for receive address |

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `size` | int | `256` | QR code size in pixels (range: 64–1024) |
| `format` | string | `png` | Output format: `png` (base64) or `ascii` |

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `address` | string | Receive address |
| `uri` | string | BIP21 URI (`bitcoin:<address>`) |
| `qr_png` | string | Base64-encoded PNG (if format=png) |
| `qr` | string | ASCII art QR code (if format=ascii) |
| `display_hint` | string | Command hint for ASCII display |

---

### Extended Public Key

#### `btc/wallets/:name/xpub`

| Operation | Description |
|-----------|-------------|
| READ | Export account-level extended public key |

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `xpub` | string | Extended public key |
| `format` | string | Key format name |
| `derivation_path` | string | BIP84/86 derivation path (e.g., `m/86'/0'/0'`) |
| `address_type` | string | Wallet address type |
| `network` | string | Bitcoin network |
| `descriptor` | string | Output descriptor template for wallet import |

**Key Format by Wallet Type:**

| Address Type | Mainnet | Testnet |
|--------------|---------|---------|
| `p2tr` | `xpub` | `tpub` |
| `p2wpkh` | `zpub` | `vpub` |

---

### PSBT Sign

#### `btc/wallets/:name/psbt/sign`

| Operation | Description |
|-----------|-------------|
| CREATE/UPDATE | Sign a PSBT with wallet keys |

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `psbt` | string | _(required)_ | Base64-encoded PSBT |

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `psbt` | string | Signed PSBT (base64) |
| `inputs_total` | int | Total number of inputs in PSBT |
| `inputs_signed` | int | Number of inputs signed by this wallet |

**Signing Strategies (tried in order):**
1. Direct address match — single-sig P2WPKH/P2TR
2. BIP32 derivation path matching — uses derivation paths in PSBT
3. Witness script scanning — multi-sig P2WSH

---

### PSBT Finalize

#### `btc/wallets/:name/psbt/finalize`

| Operation | Description |
|-----------|-------------|
| CREATE/UPDATE | Finalize a signed PSBT and optionally broadcast |

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `psbt` | string | _(required)_ | Base64-encoded signed PSBT |
| `broadcast` | bool | `true` | Whether to broadcast the transaction |

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `txid` | string | Transaction ID |
| `hex` | string | Raw transaction hex |
| `broadcast` | bool | Whether transaction was broadcast |
| `broadcast_txid` | string | Confirmed txid from broadcast (if successful) |
| `error` | string | Error message (if broadcast failed) |

---

### Consolidate

#### `btc/wallets/:name/consolidate`

| Operation | Description |
|-----------|-------------|
| CREATE/UPDATE | Consolidate multiple UTXOs into one |

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `fee_rate` | int | `10` | Fee rate in sat/vbyte |
| `min_confirmations` | int | _(from config)_ | Minimum UTXO confirmations |
| `below_value` | int | `0` | Only consolidate UTXOs below this value (0 = all) |
| `dry_run` | bool | `false` | Preview without broadcasting |
| `compact` | bool | `false` | Run compaction after consolidation |

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `txid` | string | Transaction ID (if broadcast) |
| `inputs_consolidated` | int | Number of UTXOs consolidated |
| `total_input` | int | Total value of inputs |
| `fee` | int | Transaction fee |
| `output_value` | int | Value of consolidated UTXO |
| `output_address` | string | Address receiving consolidated funds |
| `broadcast` | bool | Whether transaction was broadcast |
| `privacy_warning` | string | Warning about address linking |
| `dry_run` | bool | Present if dry_run=true |
| `estimated_fee` | int | Estimated fee (dry_run only) |
| `estimated_vsize` | int | Estimated vsize (dry_run only) |
| `compact_addresses_deleted` | int | Addresses deleted (if compact=true) |
| `compact_new_first_active` | int | New first active index (if compact=true) |

> **Privacy Warning:** Consolidation links all input addresses together via the common-input-ownership heuristic.

---

### Compact

#### `btc/wallets/:name/compact`

| Operation | Description |
|-----------|-------------|
| CREATE/UPDATE | Remove spent empty address records |

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `previous_first_active` | int | Previous lowest tracked index |
| `new_first_active` | int | New lowest tracked index |
| `addresses_deleted` | int | Number of records removed |
| `addresses_remaining` | int | Number of records remaining |

---

### Scan

#### `btc/wallets/:name/scan`

| Operation | Description |
|-----------|-------------|
| READ/CREATE/UPDATE | Scan for funds on retired or untracked addresses |

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `retired` | bool | `true` | Scan addresses below FirstActiveIndex |
| `gap` | int | `0` | Scan N addresses beyond NextAddressIndex |
| `sweep` | bool | `false` | Sweep found retired funds to fresh address |
| `fee_rate` | int | `10` | Fee rate for sweep (sat/vbyte) |

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `retired_scanned` | int | Number of retired addresses scanned |
| `retired_found` | array | Retired addresses with funds |
| `retired_total` | int | Total satoshis on retired addresses |
| `gap_scanned` | int | Number of gap addresses scanned |
| `gap_found` | array | Untracked addresses with funds |
| `gap_total` | int | Total satoshis on untracked addresses |
| `gap_registered` | array | Addresses registered from gap scan |
| `new_next_index` | int | Updated NextAddressIndex |
| `sweep_txid` | string | Sweep transaction ID |
| `sweep_fee` | int | Sweep transaction fee |
| `sweep_output` | int | Sweep output value |
| `sweep_address` | string | Sweep destination address |
| `sweep_broadcast` | bool | Whether sweep was broadcast |
| `sweep_error` | string | Sweep error (if failed) |
| `total_found` | int | Combined total from both scans |
| `message` | string | Summary message |

---

## Multi-Sig Workflow

Vault can participate as one signer in a multi-sig setup:

1. Export xpub from Vault
2. Create multi-sig wallet in Sparrow/Caravan with Vault's xpub + other signers
3. Create PSBT in the coordinator when spending
4. Sign with Vault via `/psbt/sign`
5. Collect signatures from other signers
6. Finalize and broadcast when threshold is met

**Supported multi-sig types:**
- P2WSH (Native SegWit multi-sig)
- P2SH-P2WSH (Wrapped SegWit)
- Taproot (`tr()` descriptors with script-path spends)

---

## Watch-Only Wallet Workflow

For complex transactions (multi-output, custom coin selection), use an external wallet:

1. Export xpub from Vault
2. Import into Sparrow as watch-only wallet
3. Create transaction in Sparrow
4. Export PSBT from Sparrow
5. Sign via `/psbt/sign`
6. Finalize via `/psbt/finalize`

---

## License

MIT
