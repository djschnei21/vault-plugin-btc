# Bitcoin Secret Engine Dependency Assumptions

## Vault
- `put_sealed` applies seal-wrap semantics to `wallets/{name}/secrets`
- Storage read-after-write consistency is sufficient for single-process request handling
- Storage visibility and read-after-write consistency are sufficient for storage-backed address reservation conflict detection and bounded stale-reservation recovery across plugin processes
- Plugin processes and storage nodes have clocks aligned closely enough that reservation TTL checks distinguish fresh reservations from genuinely stale ones within the configured recovery window

## BDK
- `Wallet::create(...).create_wallet_no_persist()` does not persist secrets outside the plugin process
- `Wallet::sign` only signs inputs controlled by the loaded descriptors

## bitcoin
- PSBT parsing rejects structurally invalid inputs before signing
- Transaction serialization preserves consensus-critical fields
