# vault-plugin-btc

A HashiCorp Vault secret engine plugin for Bitcoin custodial operations, written in Rust using the [Bitcoin Development Kit (BDK)](https://github.com/bitcoindevkit/bdk).

The plugin manages HD wallets, derives addresses, and signs transactions — all with private key material secured in Vault's encrypted (and optionally seal-wrapped) storage. Private keys and mnemonics are never exposed through the API.

## Features

- **HD Wallet Management** — Create wallets from BIP39 mnemonics (generated or imported)
- **Descriptor-Based** — Supports BIP44 (legacy), BIP49 (nested segwit), BIP84 (native segwit), and BIP86 (taproot)
- **Address Generation** — Deterministic address derivation with index tracking
- **PSBT Signing** — Sign Partially Signed Bitcoin Transactions with vault-managed keys
- **PSBT Utilities** — Create, decode, combine, and finalize PSBTs
- **Multi-Network** — Mainnet, testnet, signet, and regtest support
- **Seal-Wrap** — Private key material stored in Vault seal-wrap paths for hardware-backed encryption
- **Memory Safety** — Sensitive types derive `ZeroizeOnDrop` to clear secrets from memory

## Building

```bash
cargo build --release
```

The plugin binary is produced at `target/release/vault-plugin-btc`.

## Installation

### Register the plugin with Vault

```bash
# Calculate the SHA256 of the plugin binary
SHA256=$(sha256sum target/release/vault-plugin-btc | cut -d' ' -f1)

# Register
vault plugin register -sha256=$SHA256 secret vault-plugin-btc

# Enable at a mount path
vault secrets enable -path=btc vault-plugin-btc
```

### Configure the plugin

```bash
# Set network (default: testnet)
vault write btc/config network=testnet

# Read current config
vault read btc/config
```

## Quick Start

```bash
# Create a wallet (generates a new mnemonic internally)
vault write btc/wallets/my-wallet address_type=native_segwit

# Generate a receiving address
vault write -f btc/wallets/my-wallet/addresses/new

# List generated addresses
vault read btc/wallets/my-wallet/addresses

# Get extended public keys
vault read btc/wallets/my-wallet/keys

# Sign a PSBT
vault write btc/wallets/my-wallet/sign psbt="cHNidP8B..."

# List all wallets
vault list btc/wallets

# Delete a wallet
vault delete btc/wallets/my-wallet
```

---

## Deployment

### Building the Plugin

Build the plugin binary:

```bash
cargo build --release
```

The binary will be at `target/release/vault-plugin-btc`.

### Installing in Vault

1. **Copy the binary to Vault's plugin directory:**

   ```bash
   sudo cp target/release/vault-plugin-btc /usr/local/lib/vault/plugins/
   sudo chown vault:vault /usr/local/lib/vault/plugins/vault-plugin-btc
   sudo chmod 755 /usr/local/lib/vault/plugins/vault-plugin-btc
   ```

2. **Register the plugin with Vault:**

   ```bash
   # Calculate SHA256
   SHA256=$(sha256sum /usr/local/lib/vault/plugins/vault-plugin-btc | cut -d' ' -f1)

   # Register
   vault plugin register -sha256=$SHA256 secret vault-plugin-btc
   ```

3. **Enable the secret engine:**

   ```bash
   vault secrets enable -path=btc vault-plugin-btc
   ```

### Configuration

Configure the plugin after enabling:

```bash
# Set network
vault write btc/config network=testnet

# Optional: Set blockchain backend
vault write btc/config blockchain_backend_url="https://electrs.example.com:50001"
```

## Troubleshooting

### Plugin Registration Issues

**Error:** `plugin not found`

- Verify the binary is in Vault's plugin directory
- Check file permissions (readable by Vault user)
- Confirm SHA256 hash matches exactly

**Error:** `plugin failed to start`

- Check Vault logs: `journalctl -u vault`
- Ensure all dependencies are available (glibc, etc.)
- Try running the plugin manually: `./vault-plugin-btc`

### Network/Backend Issues

**Error:** `connection refused` when generating addresses

- Verify `blockchain_backend_url` is set and reachable
- For testnet, use a public Electrum server
- Check firewall settings

**Slow operations:**

- Blockchain backend may be overloaded
- Consider using a local Bitcoin node

### Permission Issues

**Error:** `permission denied` on config writes

- Config endpoints require root token
- Use `vault auth enable userpass` or similar for non-root users

### Wallet Issues

**Error:** `wallet not found`

- Check wallet name spelling
- Use `vault list btc/wallets` to verify

**Address reuse:**

- The plugin tracks derivation indices automatically
- Never reuse addresses manually

### PSBT Signing Issues

**Error:** `invalid PSBT`

- Ensure PSBT is base64-encoded
- Verify PSBT is created for the correct network
- Check that wallet contains the keys for the PSBT inputs

**Incomplete signing:**

- For multi-sig, combine signatures first
- Ensure all required keys are available in the wallet

---

## API Reference

All endpoints are accessed through the Vault CLI or HTTP API under the mount path (e.g., `btc/`). Vault operations map as follows:

| Vault CLI | Operation |
|-----------|-----------|
| `vault write` | Create / Update |
| `vault read` | Read |
| `vault delete` | Delete |
| `vault list` | List |

---

### Configuration

#### Write Configuration

```
POST /config
```

Set the plugin-wide configuration. Requires a root token.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `network` | string | No | Bitcoin network: `bitcoin`, `testnet`, `signet`, `regtest`. Default: `testnet` |
| `blockchain_backend_url` | string | No | URL for a blockchain backend (Electrum/Esplora). Empty string clears it. |

**Example:**

```bash
vault write btc/config network=testnet
```

**Response:**

```json
{
  "network": "testnet",
  "blockchain_backend_url": null
}
```

---

#### Read Configuration

```
GET /config
```

**Example:**

```bash
vault read btc/config
```

---

### Wallets

#### Create Wallet

```
POST /wallets/:name
```

Create a new HD wallet. A 24-word BIP39 mnemonic is generated automatically unless one is provided for import.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `network` | string | No | Override the plugin-wide network for this wallet. |
| `address_type` | string | No | Address type. Default: `native_segwit`. See [Address Types](#address-types). |
| `mnemonic` | string | No | BIP39 mnemonic phrase to import. If omitted, a new 24-word mnemonic is generated. |

**Example:**

```bash
# Generate a new wallet
vault write btc/wallets/treasury address_type=taproot

# Import an existing mnemonic
vault write btc/wallets/imported \
  mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
```

**Response:**

```json
{
  "name": "treasury",
  "network": "testnet",
  "address_type": "taproot",
  "created_at": 1711400000,
  "external_descriptor": "tr(tpub.../86h/1h/0h/0/*)#checksum",
  "internal_descriptor": "tr(tpub.../86h/1h/0h/1/*)#checksum"
}
```

> **Security:** The mnemonic and private descriptors are stored in Vault's seal-wrapped storage and are never returned in any API response.

---

#### Read Wallet

```
GET /wallets/:name
```

Returns public metadata for a wallet.

**Example:**

```bash
vault read btc/wallets/treasury
```

**Response:**

```json
{
  "name": "treasury",
  "network": "testnet",
  "address_type": "taproot",
  "created_at": 1711400000,
  "external_descriptor": "tr(tpub.../86h/1h/0h/0/*)#checksum",
  "internal_descriptor": "tr(tpub.../86h/1h/0h/1/*)#checksum",
  "next_external_index": 5,
  "next_internal_index": 0
}
```

---

#### Delete Wallet

```
DELETE /wallets/:name
```

Permanently deletes a wallet and all associated key material.

```bash
vault delete btc/wallets/treasury
```

---

#### List Wallets

```
LIST /wallets/
```

```bash
vault list btc/wallets
```

**Response:**

```json
{
  "keys": ["treasury", "hot-wallet", "cold-storage"]
}
```

---

### Keys

#### Get Extended Public Keys

```
GET /wallets/:name/keys
```

Returns the public descriptors (containing xpub/tpub) for the wallet.

```bash
vault read btc/wallets/treasury/keys
```

**Response:**

```json
{
  "name": "treasury",
  "network": "testnet",
  "external_descriptor": "tr(tpub.../86h/1h/0h/0/*)#checksum",
  "internal_descriptor": "tr(tpub.../86h/1h/0h/1/*)#checksum"
}
```

---

#### Derive Child Key

```
POST /wallets/:name/keys/derive
```

Derive a child public key (and its address) at a specific index or path.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `path` | string | Yes | Derivation path. Simple index (`"5"`), relative path (`"0/5"`), or absolute (`"m/0/5"`). Use `'` or `h` for hardened. |
| `keychain` | string | No | `external` (default) or `internal`/`change`. |

**Example:**

```bash
vault write btc/wallets/treasury/keys/derive path=5
```

**Response (simple index):**

```json
{
  "address": "tb1p...",
  "index": 5,
  "keychain": "external",
  "derivation_path": "5"
}
```

---

### Addresses

#### Generate New Address

```
POST /wallets/:name/addresses/new
```

Generates the next receiving address and advances the derivation index.

```bash
vault write -f btc/wallets/treasury/addresses/new
```

**Response:**

```json
{
  "address": "tb1p...",
  "index": 0,
  "keychain": "external"
}
```

Each call returns the next sequential address. The index is persisted so addresses are never reused.

---

#### List Addresses

```
GET /wallets/:name/addresses
```

Returns all addresses generated so far (index 0 through `next_external_index - 1`).

```bash
vault read btc/wallets/treasury/addresses
```

**Response:**

```json
{
  "addresses": [
    { "address": "tb1p...", "index": 0 },
    { "address": "tb1p...", "index": 1 },
    { "address": "tb1p...", "index": 2 }
  ],
  "count": 3
}
```

---

### Signing

#### Sign PSBT

```
POST /wallets/:name/sign
```

Sign a PSBT with the wallet's private keys. Returns the signed PSBT (still in PSBT format).

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `psbt` | string | Yes | Base64-encoded PSBT. |

**Example:**

```bash
vault write btc/wallets/treasury/sign psbt="cHNidP8B..."
```

**Response:**

```json
{
  "psbt": "cHNidP8B...(signed)...",
  "complete": true
}
```

`complete` is `true` if all inputs are fully signed. For multi-sig wallets, it may be `false` if additional signers are needed.

---

#### Sign and Extract Transaction

```
POST /wallets/:name/sign-raw
```

Signs a PSBT and, if signing completes, extracts the finalized raw transaction ready for broadcast.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `psbt` | string | Yes | Base64-encoded PSBT. |

**Response (complete):**

```json
{
  "signed_tx": "0200000001...",
  "txid": "abc123...",
  "complete": true
}
```

**Response (incomplete — needs more signatures):**

```json
{
  "psbt": "cHNidP8B...",
  "complete": false
}
```

---

### PSBT Utilities

#### Create PSBT

```
POST /psbt/create
```

Build an unsigned PSBT from inputs and outputs.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `inputs` | array | Yes | Array of `{"txid": "hex...", "vout": N}` objects referencing UTXOs to spend. |
| `outputs` | array | Yes | Array of `{"address": "...", "amount": N}` objects. Amount is in satoshis. |

**Example:**

```bash
vault write btc/psbt/create \
  inputs='[{"txid":"abc123...","vout":0}]' \
  outputs='[{"address":"tb1q...","amount":50000}]'
```

**Response:**

```json
{
  "psbt": "cHNidP8B...",
  "txid": "def456..."
}
```

> **Note:** The created PSBT contains no UTXO data. You must add `witness_utxo` or `non_witness_utxo` fields before signing (or use BDK's wallet signing which can populate these).

---

#### Decode PSBT

```
POST /psbt/decode
```

Inspect the structure and signing progress of a PSBT.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `psbt` | string | Yes | Base64-encoded PSBT. |

**Response:**

```json
{
  "txid": "abc123...",
  "version": 2,
  "lock_time": 0,
  "input_count": 1,
  "output_count": 2,
  "inputs": [
    {
      "index": 0,
      "witness_utxo": { "value": 100000, "script_pubkey": "0014..." },
      "partial_signatures": 1,
      "bip32_derivations": 1,
      "has_final_script_witness": true
    }
  ],
  "outputs": [
    { "index": 0, "value": 50000, "script_pubkey": "0014..." },
    { "index": 1, "value": 49500, "script_pubkey": "0014..." }
  ]
}
```

---

#### Combine PSBTs

```
POST /psbt/combine
```

Merge multiple PSBTs into one. Used in multi-signature workflows where different parties sign the same transaction independently.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `psbts` | array | Yes | Array of base64-encoded PSBT strings. All must represent the same transaction. |

**Example:**

```bash
vault write btc/psbt/combine \
  psbts='["cHNidP8B...(signer1)...","cHNidP8B...(signer2)..."]'
```

**Response:**

```json
{
  "psbt": "cHNidP8B...(combined)..."
}
```

---

#### Finalize PSBT

```
POST /psbt/finalize
```

Finalize a fully-signed PSBT and extract the raw transaction for broadcast.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `psbt` | string | Yes | Base64-encoded PSBT. |

**Response (success):**

```json
{
  "complete": true,
  "signed_tx": "0200000001...",
  "txid": "abc123..."
}
```

**Response (incomplete):**

```json
{
  "complete": false,
  "psbt": "cHNidP8B...",
  "error": "PSBT not fully finalized: ..."
}
```

---

## Address Types

| Value | Standard | Derivation Path | Address Prefix (mainnet) | Address Prefix (testnet) |
|-------|----------|-----------------|--------------------------|--------------------------|
| `legacy`, `p2pkh` | BIP44 | `m/44'/coin'/0'` | `1...` | `m...` / `n...` |
| `nested_segwit`, `nested-segwit`, `p2sh-p2wpkh` | BIP49 | `m/49'/coin'/0'` | `3...` | `2...` |
| `native_segwit`, `native-segwit`, `segwit`, `p2wpkh` | BIP84 | `m/84'/coin'/0'` | `bc1q...` | `tb1q...` |
| `taproot`, `p2tr` | BIP86 | `m/86'/coin'/0'` | `bc1p...` | `tb1p...` |

Default: `native_segwit`

## Security Model

- **No private key export** — No API endpoint returns mnemonics, private keys, or private descriptors.
- **Seal-wrap storage** — Wallet secrets are stored at `wallets/+/secrets` which is declared as a seal-wrap path. When Vault is configured with an HSM seal, these values receive an additional layer of hardware-backed encryption.
- **Memory zeroization** — The `WalletSecrets` type implements `ZeroizeOnDrop`, clearing sensitive material from memory when it goes out of scope.
- **Root-only config** — The `/config` path is declared as a root-protected path, requiring a root token to modify.
- **AutoMTLS** — Plugin-to-Vault communication uses mutual TLS with automatically generated certificates.

## Architecture

The plugin communicates with Vault using the [go-plugin](https://github.com/hashicorp/go-plugin) gRPC protocol (v5). On startup it:

1. Validates the `VAULT_BACKEND_PLUGIN` magic cookie
2. Generates a self-signed TLS certificate
3. Starts a tonic gRPC server on an ephemeral port
4. Prints the handshake line to stdout
5. Serves the Vault `Backend` gRPC interface

Wallets are reconstructed on-demand from stored descriptors using BDK's `Wallet::create().create_wallet_no_persist()`. This avoids the complexity of persisting BDK's full `ChangeSet` through Vault's KV storage — the plugin only stores wallet metadata, secrets, and derivation indices.

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| `bdk_wallet` 1.2 | Bitcoin wallet operations (descriptors, signing, addresses) |
| `bitcoin` 0.32 | Bitcoin primitives (transactions, scripts, keys) |
| `miniscript` 12 | Output descriptor parsing and public key extraction |
| `bip39` 2 | Mnemonic phrase generation and parsing |
| `tonic` 0.12 | gRPC server and client |
| `prost` 0.13 | Protocol buffer serialization |
| `rcgen` 0.13 | TLS certificate generation |
| `zeroize` 1 | Secure memory clearing |

## Multi-Signature Workflow

For multi-sig operations, use the PSBT workflow:

```bash
# 1. Create wallets for each signer
vault write btc/wallets/signer1 address_type=native_segwit
vault write btc/wallets/signer2 address_type=native_segwit

# 2. Create an unsigned PSBT
vault write btc/psbt/create \
  inputs='[{"txid":"...","vout":0}]' \
  outputs='[{"address":"tb1q...","amount":50000}]'

# 3. Sign with first signer
vault write btc/wallets/signer1/sign psbt="<unsigned_psbt>"

# 4. Sign with second signer
vault write btc/wallets/signer2/sign psbt="<unsigned_psbt>"

# 5. Combine the two signed PSBTs
vault write btc/psbt/combine \
  psbts='["<signed_by_1>","<signed_by_2>"]'

# 6. Finalize and extract the transaction
vault write btc/psbt/finalize psbt="<combined_psbt>"
```

## License

MPL-2.0
