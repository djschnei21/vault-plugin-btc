# Bitcoin Secret Engine Threat Model

## Assets
- Mnemonic phrases
- Private descriptors
- Signing capability
- Wallet metadata integrity
- Address derivation state

## Primary Adversary
- Remote API attacker who can issue Vault requests but has no host or storage access

## Trust Boundaries
- Remote caller -> Vault request path and operation
- Vault request -> handler validation and parsing
- Handler -> storage interface
- Storage -> wallet reconstruction
- Wallet reconstruction -> BDK and `bitcoin` signing behavior

## Security Invariants
- Secret material never leaves sealed storage through API responses, logs, or errors
- Malformed requests fail closed
- Signing stays confined to wallet-owned descriptors
- Mutable derivation state cannot be corrupted by concurrent requests

## Out of Scope
- Full host compromise
- Full Vault deployment review
- Formal external certification
