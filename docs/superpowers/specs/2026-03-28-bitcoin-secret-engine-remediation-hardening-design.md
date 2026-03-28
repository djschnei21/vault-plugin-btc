# Bitcoin Secret Engine Remediation Hardening Design

## Goal

Remediate the remaining security backlog from the audit by tightening signing policy checks,
reducing descriptor disclosure on standard read paths, and replacing process-local address
allocation protection with storage-coordinated cross-process safety.

## Scope

This design covers three remediation tracks that were explicitly left in the backlog:

- `sign` and `sign-raw` admission-control hardening.
- Descriptor disclosure reduction for normal wallet and key reads.
- Cross-process-safe address allocation.

This design stays within the remote API attacker threat model already defined by the audit.

## Non-Goals

- Full Vault HA coordination design beyond what this plugin needs for address reservation.
- New operator-facing authorization systems or policy engines.
- A general-purpose descriptor export API.
- Reworking wallet persistence formats beyond what is needed for safe coordination.

## Recommended Approach

Three approaches were considered:

1. Handler-only validation with no storage coordination changes.
2. Focused hardening across handlers plus storage-backed address reservation.
3. Broad API and storage redesign.

The recommended approach is option 2. It closes the real gaps identified by the audit while
preserving the current architecture: handlers remain responsible for request admission and
response shaping, and `WalletManager` remains responsible for state transitions and wallet-backed
operations.

## Architecture

The remediation is split into three bounded components.

### 1. Signing Admission Control

`src/handlers/sign.rs` becomes the explicit policy gate before any call to `wallet.sign(...)`.

Responsibilities:

- Parse and decode the submitted PSBT.
- Load wallet metadata and wallet descriptors.
- Validate that the PSBT only uses supported script policy within reviewed scope.
- Reject unsafe requests with `Error::InvalidRequest` before invoking BDK signing.

Policy rules for this pass:

- Reject any signing attempt where available UTXO/script context implies unsupported script policy.
- Fail closed when required inspection context is absent or ambiguous.

The intent is not to replace BDK's signing correctness checks. The plugin adds a narrower custody
policy layer so a remote caller cannot rely on implicit library behavior for authority expansion.
Network selection remains mount-level configuration rather than a per-request signing parameter.

### 2. Descriptor Disclosure Reduction

`src/handlers/wallets.rs` and `src/handlers/keys.rs` stop returning full public descriptors on the
standard `GET /wallets/:name` and `GET /wallets/:name/keys` paths.

The default response becomes minimal wallet identity metadata:

- `name`
- `network`
- `address_type`
- `has_external_keychain`
- `has_internal_keychain`

The existing derive endpoint remains available, but only for the already-audited safe mode of a
single unhardened index relative to a named keychain.

This keeps normal operational introspection while avoiding disclosure of reusable public wallet
structure to any caller who can hit either endpoint.

### 3. Cross-Process Address Reservation

`src/wallet/manager.rs` becomes the source of truth for external address reservation. The current
process-local mutex in `src/wallet/locks.rs` remains useful as a local contention reducer, but it
is no longer the primary integrity mechanism.

The durable flow is:

1. Acquire the local per-wallet async mutex.
2. Read wallet metadata from storage.
3. Attempt to claim the current external index through a storage-backed reservation record.
4. Persist the incremented metadata state.
5. Clear or retire the reservation record.
6. Return the derived address for the claimed index.

If the reservation record already exists and is still fresh, the request fails closed or retries
within a bounded window. If the reservation is stale, the manager may reclaim it.

This design makes storage, not process memory, the coordination boundary.

## Data Model Changes

Add a reservation record under the wallet namespace, for example:

- `wallets/{name}/address-reservation`

The record stores:

- Reserved external index.
- Reservation timestamp.
- Reservation nonce or holder id.

The metadata document remains the canonical counter, but reservation records protect in-flight
updates across multiple plugin processes that share storage.

No private material storage changes are required.

## Request and Response Changes

### `GET /wallets/:name` and `GET /wallets/:name/keys`

Current behavior exposes `external_descriptor` and `internal_descriptor`.

New behavior returns minimal metadata only. This is a deliberate response-shape change because the
existing defaults are treated as over-disclosure in the audited threat model.

### `POST /wallets/:name/sign`

Behavior stays functionally the same for valid requests, but requests now fail earlier when the
PSBT uses unsupported script policy or omits required inspection context.

### `POST /wallets/:name/sign-raw`

Behavior matches `sign`, since the endpoint already accepts PSBT input in practice.

### `POST /wallets/:name/addresses/new`

Successful responses are unchanged. Failure modes may now include bounded reservation conflicts or
stale-lock recovery errors instead of silent duplicate allocation risk.

## Error Handling

All new protections fail closed.

- Validation failures return `Error::InvalidRequest` with stable, specific messages.
- Reservation conflicts return a deterministic internal or invalid-state error that does not leak
  secrets.
- Stale reservation recovery is explicit and bounded.

Errors must not include descriptor contents, mnemonic material, raw secret storage values, or
unredacted PSBT internals.

## Testing Strategy

Add focused regression coverage in separate security-oriented test files.

### Signing Policy Tests

- Unsupported script policy is rejected.
- Ambiguous or insufficient PSBT inspection context fails closed.

### Descriptor Disclosure Tests

- `GET /wallets/:name` no longer includes descriptor strings.
- `GET /wallets/:name/keys` no longer includes descriptor strings.
- Expected minimal metadata fields remain present.
- `keys/derive` still works for valid single-index requests.

### Address Reservation Tests

- Manager-level reservation conflicts do not allocate the same index twice.
- Stale reservations can be recovered safely.
- Sequential successful reservations still return unique indices.
- Existing in-process concurrency test continues to pass.

## Rollout Order

Implement in this order:

1. Signing policy checks and tests.
2. Descriptor disclosure response change and tests.
3. Storage-backed address reservation and tests.
4. Security document updates reflecting the remediated backlog items.

This order reduces risk because the first two tasks are handler-scoped and easier to verify before
changing storage coordination behavior.

## Success Criteria

This remediation is complete when:

- Signing endpoints reject unsupported-policy or context-ambiguous requests before invoking signing.
- Standard wallet and key-read responses do not disclose public descriptors.
- Address allocation is protected against duplicate reservation across multiple plugin processes
  sharing storage.
- Each new protection has regression coverage.
- The security backlog and abuse matrix are updated to reflect the new state.
