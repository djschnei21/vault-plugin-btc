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
- Fix Direction: Reject invalid JSON before handler dispatch

## Remediation Backlog
- [ ] Review `sign` and `sign-raw` for mixed-network and unsupported-script policy checks
- [ ] Review descriptor disclosure endpoints for privacy and metadata leakage trade-offs
- [ ] Validate whether the address-allocation lock needs a cross-process coordination strategy
