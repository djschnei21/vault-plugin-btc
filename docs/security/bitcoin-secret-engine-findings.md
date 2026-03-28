# Bitcoin Secret Engine Findings

## Severity Scale
- High: remote attacker can expand authority, obtain signatures unexpectedly, or expose sensitive material
- Medium: remote attacker can cause incorrect state transitions, denial, or privacy-impacting behavior
- Low: hardening gap with limited exploitability inside the reviewed scope

## Findings

### F-001: Malformed JSON was previously coerced into an empty object
- Severity: Medium
- Surface: `src/router/mod.rs`
- Attacker Goal: Reach handlers with unintended default state
- Evidence: `tests/security_router_fail_closed.rs`
- Status: Remediated
- Remediation: Router rejects invalid JSON before handler dispatch
- Residual Risk: Body-size limits and parser behavior should still be regression-tested when request handling changes

### F-002: Default wallet and key reads exposed reusable public descriptors
- Severity: Medium
- Surface: `src/handlers/wallets.rs`, `src/handlers/keys.rs`
- Attacker Goal: Learn reusable wallet structure from ordinary read paths
- Evidence: `tests/security_descriptor_privacy.rs`
- Status: Remediated
- Remediation: Default wallet and key reads now return minimal metadata and keychain presence flags without descriptor strings
- Residual Risk: Explicit derivation flows still disclose wallet-derived public data by design and should remain tightly scoped

### F-003: Address allocation relied on process-local coordination
- Severity: Medium
- Surface: `src/wallet/manager.rs`
- Attacker Goal: Trigger duplicate external index allocation across plugin processes sharing storage
- Evidence: `tests/security_state_integrity.rs`, `tests/security_address_reservation.rs`
- Status: Remediated with storage dependency assumptions
- Remediation: Address allocation now uses storage-backed reservations to block fresh conflicts and reclaim stale reservations before advancing metadata
- Residual Risk: Correctness depends on shared storage providing timely read-after-write visibility for reservation records; a fresh reservation can also cause bounded denial until it expires

### F-004: Signing policy did not fail closed when required PSBT inspection context was absent
- Severity: High
- Surface: `src/handlers/sign.rs`
- Attacker Goal: Reach the signer without enough script or UTXO context for policy inspection
- Evidence: `tests/security_sign_policy.rs`
- Status: Remediated within the approved scope
- Remediation: Signing requests are rejected before signing when required witness UTXO or nested-segwit redeem-script context is missing or inconsistent
- Residual Risk: Additional signing-policy hardening remains open outside this remediation scope

## Remediation Backlog
- [x] Reject malformed JSON before handler dispatch
- [x] Remove descriptor disclosure from default wallet and key reads
- [x] Add storage-backed reservation conflict detection and stale-reservation recovery for address allocation
- [x] Fail closed when required PSBT script or UTXO inspection context is absent
- [ ] Continue reviewing signing policy coverage beyond the currently approved remediation scope
- [ ] Revalidate reservation behavior if the plugin is deployed on storage backends with weaker consistency characteristics
