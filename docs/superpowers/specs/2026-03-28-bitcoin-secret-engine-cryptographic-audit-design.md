# Bitcoin Secret Engine Cryptographic Audit Design

## Goal

Plan a full cryptographic audit of the Bitcoin secret engine as an internal hardening exercise.
The audit is optimized to find and fix real issues quickly, not to prepare a formal certification package.

## Audit Intent

- Use a risk-first audit methodology.
- Treat the plugin as a custody boundary.
- Use a remote API attacker as the primary adversary.
- Include critical upstream dependency and integration assumptions where they materially affect safety.

## Scope

The audit covers the plugin as a custody boundary for a remote API attacker, with upstream Vault, BDK, and `bitcoin` behavior included only where it materially changes the engine's exposure.

Primary goals:

- Prevent secret exfiltration.
- Prevent unauthorized or unsafe signing.
- Confirm descriptor and key-derivation correctness.
- Identify request-driven denial, misuse, or state-corruption paths.

In-scope surfaces:

- Wallet creation and import.
- Metadata and secret persistence.
- Address derivation.
- PSBT parsing, combination, finalization, and signing.
- Route exposure and operation matching.
- Request validation and parsing behavior.
- Error and logging behavior.
- Assumptions made about Vault storage and critical crypto dependencies.

Out of scope:

- Full host-compromise resistance.
- Full Vault deployment review.
- Formal certification or control-framework mapping.

Out-of-scope items must still be captured as explicit assumptions or residual risks when they affect conclusions.

## Recommended Approach

Three approaches were considered:

1. Risk-first audit.
2. Code-surface audit.
3. Requirements-first audit.

The recommended approach is the risk-first audit because it concentrates effort on the most important attacker goals first: key exfiltration, unauthorized signing, descriptor misuse, PSBT abuse, storage leakage, and boundary mistakes between request handling, Vault storage, and BDK signing.

## Audit Architecture

The audit runs in five passes:

1. Threat modeling.
2. Asset and control inventory.
3. Code review by attack path.
4. Adversarial testing.
5. Findings triage.

The review begins by identifying the assets that must never be compromised:

- Mnemonic material.
- Private descriptors.
- Derived signing capability.
- Wallet metadata integrity.
- Derivation state.
- Outputs that could enable unauthorized spend or privacy loss.

The review then maps trust boundaries:

- Remote caller -> Vault request routing -> handler validation and parsing -> wallet reconstruction -> storage reads and writes -> BDK and `bitcoin` signing primitives.

Code review is driven by attacker goals rather than by file boundaries. High-value attack paths include:

- Unauthorized wallet creation or import behavior.
- Route or path confusion.
- Descriptor disclosure beyond intended visibility.
- PSBT abuse or parser confusion.
- Replay or signer-confusion scenarios.
- Index races during address generation.
- Request patterns that force unsafe state transitions or denial of service.

Dependency review stays narrow and verifies only the assumptions this plugin depends on for safety:

- Vault storage semantics.
- BDK wallet reconstruction and signing behavior.
- PSBT parsing and combination rules.
- Bitcoin key, descriptor, and transaction primitives.

Findings are ranked into these buckets so remediation order stays obvious:

- Cryptographic correctness.
- Authorization and boundary weakness.
- State integrity.
- Input handling.
- Operational hardening gaps.

## Workstreams

### 1. Threat Model and Security Invariants

Define the conditions that must always hold:

- Private material never leaves sealed storage through any API path.
- Public metadata never enables private recovery.
- Signing never authorizes keys outside the wallet's intended descriptors.
- Malformed requests fail closed.
- Concurrent requests cannot corrupt derivation state or expand authority.

Outputs:

- Threat model.
- Security invariant list.
- Trust-boundary diagram.
- Assumption register.

### 2. Key Material Lifecycle Review

Inspect the full lifecycle of secret material:

- Mnemonic generation and import.
- Seed derivation.
- Xpriv handling.
- Descriptor construction.
- Sealed versus unsealed persistence.
- Memory lifetime and clone behavior.
- Drop and zeroization boundaries.
- Logging, error, and serialization paths that could expose secrets.

Primary questions:

- Where can secret material appear in memory or serialized form?
- Which copies are intentionally made, and how long do they survive?
- Are there any accidental disclosure paths through tracing, error strings, or metadata?

### 3. Signing and Transaction Safety Review

Analyze all transaction-handling paths:

- PSBT decode.
- PSBT combine.
- PSBT finalize.
- PSBT signing.
- Any raw-signing compatibility paths.

Review goals:

- Detect parser abuse and malformed-PSBT handling flaws.
- Detect signer confusion or unsupported-script edge cases.
- Detect mixed-network or mixed-context inputs that should fail.
- Detect missing policy checks that let a remote caller obtain signatures beyond intended custody behavior.

### 4. State Integrity and Concurrency Review

Inspect all mutable state transitions:

- Wallet creation and deletion.
- Metadata updates.
- Address index advancement.
- List and read consistency.
- Race windows and lost-update behavior.

Review goals:

- Determine whether concurrent requests can cause address reuse.
- Determine whether stale reads can overwrite newer state.
- Determine whether duplicate wallet or delete/create races can leave inconsistent storage.

### 5. Boundary and Dependency Review

Inspect the interfaces that define the plugin's exposure:

- Request routing.
- Operation and path matching.
- JSON parsing and fallback behavior.
- Error mapping and response shaping.
- Storage API assumptions.
- BDK and `bitcoin` dependency assumptions.

Review goals:

- Verify the plugin fails closed when inputs are malformed or operations do not match the route.
- Identify any dependency behavior that silently widens the plugin's authority or ambiguity.

### 6. Adversarial Testing

Add targeted tests and manual abuse cases for:

- Malformed PSBTs.
- Hostile derivation paths.
- Oversized payloads.
- Mixed operation and path cases.
- Duplicate wallet creation races.
- Repeated address-generation contention.
- State transitions around delete, read, and sign.

Testing types:

- Negative tests.
- Property-style tests where practical.
- Concurrency tests for shared mutable state.
- Manual abuse matrix for edge cases not well covered by unit tests.

## Deliverables

The audit should produce:

- A risk-ranked audit report.
- A trust-boundary diagram.
- A security invariants list.
- An attack-surface inventory.
- A dependency-assumption register.
- An abuse-case matrix.
- A remediation backlog ordered by risk and effort.

Each finding should include:

- Attacker goal.
- Affected surface.
- Exploit sketch.
- Impact.
- Recommended fix direction.
- Confidence level.

## Evidence Requirements

High-risk areas require explicit evidence, not only reviewer opinion.

Required evidence areas:

- Malformed PSBT handling.
- Route and operation parsing.
- Wallet lifecycle edge cases.
- Concurrency around address and index state.

If an area remains review-only, the audit output must say so explicitly.

## Exit Criteria

The internal hardening pass is complete when:

- No unresolved high-severity findings remain within the remote-attacker scope.
- Critical assumptions about Vault, BDK, and `bitcoin` are documented.
- All accepted fixes have regression coverage.
- Residual risks are intentional, explicit, and written down.

## Recommended Sequencing

Use two phases:

1. Produce findings quickly through threat-model-led review and abuse testing.
2. Implement and verify remediations in descending risk order.

This keeps the audit focused on rapid hardening while still producing reusable security artifacts for later external review.
