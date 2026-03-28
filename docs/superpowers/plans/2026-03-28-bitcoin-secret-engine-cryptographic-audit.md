# Bitcoin Secret Engine Cryptographic Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute a risk-first internal hardening audit of the Bitcoin secret engine, producing concrete security artifacts, targeted regression tests, and a prioritized remediation backlog for the remote API attacker scope.

**Architecture:** Turn the approved audit scope into two concrete outputs in parallel: executable security checks in Rust and durable audit artifacts in Markdown. The code path focuses on fail-closed request handling, strict derivation and signing boundaries, PSBT abuse resistance, and address-state integrity; the documentation path captures the threat model, assumptions, abuse cases, findings, and remediation sequence.

**Tech Stack:** Rust, Tokio, serde_json, Vault plugin protobuf request routing, BDK, `bitcoin`, Markdown, `cargo test`

---

## File Structure

- Create: `tests/common/mod.rs` - shared in-memory storage, request builders, and JSON response helpers for security tests.
- Create: `tests/security_router_fail_closed.rs` - fail-closed request parsing, operation matching, and payload-size tests.
- Create: `tests/security_key_boundary.rs` - derivation path and keychain-boundary tests.
- Create: `tests/security_psbt_abuse.rs` - hostile PSBT, combine-limit, and malformed-payload tests.
- Create: `tests/security_state_integrity.rs` - duplicate wallet, delete/create ordering, and address-index contention tests.
- Create: `src/wallet/locks.rs` - process-local per-wallet async lock registry for serializing mutable wallet operations.
- Modify: `src/wallet/mod.rs` - export wallet locking support.
- Modify: `src/router/mod.rs` - reject malformed JSON and oversized request bodies instead of silently coercing them.
- Modify: `src/handlers/keys.rs` - reject unknown keychains and unsupported derivation path shapes.
- Modify: `src/handlers/psbt.rs` - enforce request-shape and combine-count limits for hostile PSBT inputs.
- Modify: `src/handlers/addresses.rs` - route address allocation through a serialized wallet-state update path.
- Modify: `src/wallet/manager.rs` - add locked helpers for address allocation and mutable wallet state.
- Create: `docs/security/bitcoin-secret-engine-threat-model.md` - assets, trust boundaries, invariants, attacker goals, and out-of-scope assumptions.
- Create: `docs/security/bitcoin-secret-engine-dependency-assumptions.md` - Vault, BDK, and `bitcoin` assumptions that affect safety.
- Create: `docs/security/bitcoin-secret-engine-abuse-matrix.md` - attack cases, expected behavior, evidence, and follow-up.
- Create: `docs/security/bitcoin-secret-engine-findings.md` - risk-ranked findings log and remediation backlog.

## Implementation Notes

- Keep the test harness isolated in `tests/common/mod.rs`; do not mutate production storage interfaces just for tests.
- Use unit-level hardening only where the security review already identifies a concrete fail-open or race condition.
- Prefer small constants for remote-attacker abuse limits and define them next to the guarded code.
- Make every hardening change land with a regression test in the same task.
- Use frequent commits after each task; do not batch unrelated hardening changes together.

### Task 1: Build the Security Test Harness

**Files:**
- Create: `tests/common/mod.rs`
- Create: `tests/security_router_fail_closed.rs`

- [ ] **Step 1: Write the first failing harness test**

```rust
mod common;

use common::{request, InMemoryStorage};
use std::sync::Arc;
use vault_plugin_btc::router::Router;

#[tokio::test]
async fn valid_empty_config_read_routes_through_test_harness() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());
    let response = router
        .route(&request("read", "config", None), storage)
        .await
        .expect("router should accept a valid read request");

    assert!(response.data.contains("testnet"));
}
```

- [ ] **Step 2: Run the test to verify the harness does not compile yet**

Run: `cargo test --test security_router_fail_closed valid_empty_config_read_routes_through_test_harness -- --exact`
Expected: FAIL with a compile error for missing `tests/common/mod.rs` items.

- [ ] **Step 3: Write the minimal shared harness implementation**

```rust
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::sync::Arc;
use tokio::sync::Mutex;
use vault_plugin_btc::proto::pb::Request as PbRequest;
use vault_plugin_btc::storage::Storage;

#[derive(Default, Clone)]
pub struct InMemoryStorage {
    inner: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Storage for InMemoryStorage {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, Box<dyn StdError>> {
        Ok(self.inner.lock().await.get(key).cloned())
    }

    async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), Box<dyn StdError>> {
        self.inner.lock().await.insert(key.to_string(), value);
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), Box<dyn StdError>> {
        self.inner.lock().await.remove(key);
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, Box<dyn StdError>> {
        let mut keys = self
            .inner
            .lock()
            .await
            .keys()
            .filter_map(|key| key.strip_prefix(prefix).map(str::to_string))
            .collect::<Vec<_>>();
        keys.sort();
        keys.dedup();
        Ok(keys)
    }

    async fn put_sealed(&self, key: &str, value: Vec<u8>) -> Result<(), Box<dyn StdError>> {
        self.put(key, value).await
    }
}

pub fn request(operation: &str, path: &str, data: Option<Value>) -> PbRequest {
    PbRequest {
        operation: operation.to_string(),
        path: path.to_string(),
        data: data.map(|value| value.to_string()).unwrap_or_default(),
        ..Default::default()
    }
}
```

- [ ] **Step 4: Run the harness test and confirm it passes**

Run: `cargo test --test security_router_fail_closed valid_empty_config_read_routes_through_test_harness -- --exact`
Expected: PASS.

- [ ] **Step 5: Commit the harness setup**

```bash
git add tests/common/mod.rs tests/security_router_fail_closed.rs
git commit -m "test: add security audit test harness"
```

### Task 2: Make Request Parsing Fail Closed

**Files:**
- Modify: `tests/security_router_fail_closed.rs`
- Modify: `src/router/mod.rs`

- [ ] **Step 1: Add failing tests for malformed JSON, list routing, and oversized bodies**

```rust
mod common;

use common::{request, InMemoryStorage};
use std::sync::Arc;
use vault_plugin_btc::error::Error;
use vault_plugin_btc::proto::pb::Request as PbRequest;
use vault_plugin_btc::router::Router;

#[tokio::test]
async fn invalid_json_request_is_rejected() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());
    let request = PbRequest {
        operation: "update".to_string(),
        path: "config".to_string(),
        data: "{\"network\":".to_string(),
        ..Default::default()
    };

    let err = router
        .route(&request, storage)
        .await
        .expect_err("invalid JSON must not be coerced into an empty object");

    assert!(matches!(err, Error::InvalidRequest(message) if message.contains("invalid JSON")));
}

#[tokio::test]
async fn read_does_not_match_list_route() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());

    let err = router
        .route(&request("read", "wallets", None), storage)
        .await
        .expect_err("read must not match the list-only route");

    assert!(matches!(err, Error::UnsupportedOperation(_, _) | Error::UnsupportedPath(_)));
}

#[tokio::test]
async fn oversized_request_body_is_rejected() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());
    let too_large = "a".repeat(65 * 1024);
    let request = PbRequest {
        operation: "update".to_string(),
        path: "config".to_string(),
        data: format!("{{\"network\":\"{}\"}}", too_large),
        ..Default::default()
    };

    let err = router
        .route(&request, storage)
        .await
        .expect_err("oversized request bodies must be rejected early");

    assert!(matches!(err, Error::InvalidRequest(message) if message.contains("request body too large")));
}
```

- [ ] **Step 2: Run the router test file and confirm the new cases fail**

Run: `cargo test --test security_router_fail_closed -- --nocapture`
Expected: FAIL because invalid JSON is currently coerced into `{}` and no size limit exists.

- [ ] **Step 3: Implement strict request parsing in the router**

```rust
const MAX_REQUEST_DATA_BYTES: usize = 64 * 1024;

// inside Router::route
let data = if request.data.is_empty() {
    serde_json::Value::Object(serde_json::Map::new())
} else {
    if request.data.len() > MAX_REQUEST_DATA_BYTES {
        return Err(Error::InvalidRequest(format!(
            "request body too large: {} bytes",
            request.data.len()
        )));
    }

    serde_json::from_str(&request.data)
        .map_err(|e| Error::InvalidRequest(format!("invalid JSON body: {e}")))?
};
```

- [ ] **Step 4: Run the router test file again and confirm it passes**

Run: `cargo test --test security_router_fail_closed -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Commit the fail-closed router hardening**

```bash
git add tests/security_router_fail_closed.rs src/router/mod.rs
git commit -m "fix: fail closed on malformed vault requests"
```

### Task 3: Tighten Key-Derivation Boundaries

**Files:**
- Create: `tests/security_key_boundary.rs`
- Modify: `src/handlers/keys.rs`

- [ ] **Step 1: Add failing tests for unknown keychains and unsupported path shapes**

```rust
mod common;

use common::{request, InMemoryStorage};
use std::sync::Arc;
use vault_plugin_btc::error::Error;
use vault_plugin_btc::router::Router;

#[tokio::test]
async fn derive_key_rejects_unknown_keychain() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());

    let err = router
        .route(
            &request(
                "update",
                "wallets/test-wallet/keys/derive",
                Some(serde_json::json!({
                    "path": "7",
                    "keychain": "sideways"
                })),
            ),
            storage,
        )
        .await
        .expect_err("unknown keychain values must be rejected");

    assert!(matches!(err, Error::InvalidRequest(message) if message.contains("invalid keychain")));
}

#[tokio::test]
async fn derive_key_rejects_multi_segment_path() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());

    let err = router
        .route(
            &request(
                "update",
                "wallets/test-wallet/keys/derive",
                Some(serde_json::json!({
                    "path": "0/7",
                    "keychain": "external"
                })),
            ),
            storage,
        )
        .await
        .expect_err("multi-segment derivation must be rejected for this endpoint");

    assert!(matches!(err, Error::InvalidRequest(message) if message.contains("single unhardened index")));
}
```

- [ ] **Step 2: Run the key-boundary tests and verify they fail**

Run: `cargo test --test security_key_boundary -- --nocapture`
Expected: FAIL because unknown keychains currently fall back to `external` and unsupported paths return descriptor data.

- [ ] **Step 3: Implement strict keychain and derivation parsing**

```rust
fn parse_keychain(value: &str) -> Result<bdk_wallet::KeychainKind, Error> {
    match value {
        "external" => Ok(bdk_wallet::KeychainKind::External),
        "internal" | "change" => Ok(bdk_wallet::KeychainKind::Internal),
        other => Err(Error::InvalidRequest(format!("invalid keychain: {other}"))),
    }
}

fn parse_single_index(path_str: &str) -> Result<u32, Error> {
    if path_str.contains('/') {
        return Err(Error::InvalidRequest(
            "path must be a single unhardened index relative to the selected keychain".to_string(),
        ));
    }

    path_str
        .parse::<u32>()
        .map_err(|_| Error::InvalidRequest(format!("invalid derivation index: {path_str}")))
}

// inside derive_key
let keychain_value = ctx
    .data
    .get("keychain")
    .and_then(|v| v.as_str())
    .unwrap_or("external");

let keychain_kind = parse_keychain(keychain_value)?;
let index = parse_single_index(path_str)?;
let address = wallet.peek_address(keychain_kind, index);

return Ok(ok_response(serde_json::json!({
    "address": address.address.to_string(),
    "index": index,
    "keychain": keychain_value,
    "derivation_path": path_str,
})));
```

- [ ] **Step 4: Run the key-boundary tests and confirm they pass**

Run: `cargo test --test security_key_boundary -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Commit the derivation-boundary hardening**

```bash
git add tests/security_key_boundary.rs src/handlers/keys.rs
git commit -m "fix: enforce strict key derivation boundaries"
```

### Task 4: Add Hostile PSBT Regression Coverage

**Files:**
- Create: `tests/security_psbt_abuse.rs`
- Modify: `src/handlers/psbt.rs`

- [ ] **Step 1: Add failing tests for combine limits and malformed PSBT payloads**

```rust
mod common;

use common::{request, InMemoryStorage};
use std::sync::Arc;
use vault_plugin_btc::error::Error;
use vault_plugin_btc::router::Router;

#[tokio::test]
async fn combine_psbt_rejects_excessive_batch_size() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());
    let psbts = vec!["cHNidP8BAAoCAAAAAQ=="; 33];

    let err = router
        .route(
            &request(
                "update",
                "psbt/combine",
                Some(serde_json::json!({ "psbts": psbts })),
            ),
            storage,
        )
        .await
        .expect_err("oversized PSBT combine batches must be rejected");

    assert!(matches!(err, Error::InvalidRequest(message) if message.contains("too many PSBTs")));
}

#[tokio::test]
async fn decode_psbt_rejects_non_string_entries_before_deserialization() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());

    let err = router
        .route(
            &request(
                "update",
                "psbt/combine",
                Some(serde_json::json!({ "psbts": [true, 7, {}] })),
            ),
            storage,
        )
        .await
        .expect_err("non-string PSBT entries must fail validation");

    assert!(matches!(err, Error::InvalidRequest(message) if message.contains("not a string")));
}
```

- [ ] **Step 2: Run the PSBT abuse test file and verify at least the size-limit case fails**

Run: `cargo test --test security_psbt_abuse -- --nocapture`
Expected: FAIL because the combine endpoint does not yet cap request batch size.

- [ ] **Step 3: Add explicit PSBT abuse limits in the handler**

```rust
const MAX_COMBINE_PSBTS: usize = 32;
const MAX_CREATE_INPUTS: usize = 128;
const MAX_CREATE_OUTPUTS: usize = 128;

fn parse_combine_psbt_request(data: &serde_json::Value) -> Result<CombinePsbtRequest, Error> {
    if data.get("psbts").is_none() {
        return Err(Error::InvalidRequest(
            "missing 'psbts' array parameter".to_string(),
        ));
    }

    validate_combine_psbt_entries(data)?;
    let request: CombinePsbtRequest = validate_json(data)?;

    if request.psbts.len() > MAX_COMBINE_PSBTS {
        return Err(Error::InvalidRequest(format!(
            "too many PSBTs: maximum is {MAX_COMBINE_PSBTS}"
        )));
    }

    Ok(request)
}

fn parse_create_psbt_request(data: &serde_json::Value) -> Result<CreatePsbtRequest, Error> {
    // existing required-field checks stay in place
    validate_create_psbt_entries(data)?;
    let request: CreatePsbtRequest = validate_json(data)?;

    if request.inputs.len() > MAX_CREATE_INPUTS {
        return Err(Error::InvalidRequest(format!(
            "too many inputs: maximum is {MAX_CREATE_INPUTS}"
        )));
    }
    if request.outputs.len() > MAX_CREATE_OUTPUTS {
        return Err(Error::InvalidRequest(format!(
            "too many outputs: maximum is {MAX_CREATE_OUTPUTS}"
        )));
    }

    Ok(request)
}
```

- [ ] **Step 4: Run the PSBT abuse test file again and confirm it passes**

Run: `cargo test --test security_psbt_abuse -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Commit the PSBT abuse hardening**

```bash
git add tests/security_psbt_abuse.rs src/handlers/psbt.rs
git commit -m "test: add hostile PSBT abuse coverage"
```

### Task 5: Serialize Address Allocation and Wallet State Updates

**Files:**
- Create: `tests/security_state_integrity.rs`
- Create: `src/wallet/locks.rs`
- Modify: `src/wallet/mod.rs`
- Modify: `src/wallet/manager.rs`
- Modify: `src/handlers/addresses.rs`

- [ ] **Step 1: Add a failing concurrency test for address allocation**

```rust
mod common;

use common::{request, InMemoryStorage};
use std::sync::Arc;
use vault_plugin_btc::router::Router;

#[tokio::test]
async fn concurrent_new_address_requests_produce_unique_indices() {
    let storage = Arc::new(InMemoryStorage::new());
    let bootstrap_router = Router::new();

    bootstrap_router
        .route(
            &request(
                "create",
                "wallets/race-wallet",
                Some(serde_json::json!({
                    "network": "testnet",
                    "address_type": "native_segwit"
                })),
            ),
            storage.clone(),
        )
        .await
        .expect("wallet bootstrap must succeed");

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let router = Router::new();
        let storage = storage.clone();
        tasks.push(tokio::spawn(async move {
            let response = router
                .route(
                    &request("update", "wallets/race-wallet/addresses/new", Some(serde_json::json!({}))),
                    storage,
                )
                .await
                .expect("address allocation must succeed");

            let json: serde_json::Value = serde_json::from_str(&response.data).unwrap();
            json["index"].as_u64().unwrap()
        }));
    }

    let mut indices = Vec::new();
    for task in tasks {
        indices.push(task.await.unwrap());
    }
    indices.sort_unstable();

    assert_eq!(indices, vec![0, 1, 2, 3, 4, 5, 6, 7]);
}
```

- [ ] **Step 2: Run the state-integrity test file and confirm the race is reproducible**

Run: `cargo test --test security_state_integrity concurrent_new_address_requests_produce_unique_indices -- --exact --nocapture`
Expected: FAIL intermittently or consistently with duplicate indices or out-of-order state.

- [ ] **Step 3: Add a per-wallet async lock and move address allocation behind it**

```rust
// src/wallet/locks.rs
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use tokio::sync::Mutex;

fn registry() -> &'static Mutex<HashMap<String, Arc<Mutex<()>>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, Arc<Mutex<()>>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

pub async fn wallet_lock(name: &str) -> Arc<Mutex<()>> {
    let mut registry = registry().lock().await;
    registry
        .entry(name.to_string())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}
```

```rust
// src/wallet/manager.rs
pub async fn next_external_address(
    storage: Arc<dyn Storage + Send + Sync>,
    name: &str,
) -> Result<(String, u32), Box<dyn std::error::Error>> {
    let wallet_lock = crate::wallet::locks::wallet_lock(name).await;
    let _guard = wallet_lock.lock().await;

    let mut metadata = Self::get_metadata(storage.clone(), name).await?;
    let (wallet, _) = Self::load_bdk_wallet(storage.clone(), name).await?;
    let index = metadata.next_external_index;
    let address = wallet
        .peek_address(bdk_wallet::KeychainKind::External, index)
        .address
        .to_string();

    metadata.next_external_index = index + 1;
    Self::update_metadata(storage, &metadata).await?;

    Ok((address, index))
}
```

```rust
// src/handlers/addresses.rs
let (address, index) = WalletManager::next_external_address(ctx.storage.clone(), name).await?;

Ok(ok_response(serde_json::json!({
    "address": address,
    "index": index,
    "keychain": "external",
})))
```

- [ ] **Step 4: Run the state-integrity tests and confirm they pass**

Run: `cargo test --test security_state_integrity -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Commit the state-integrity hardening**

```bash
git add tests/security_state_integrity.rs src/wallet/locks.rs src/wallet/mod.rs src/wallet/manager.rs src/handlers/addresses.rs
git commit -m "fix: serialize wallet address allocation"
```

### Task 6: Write the Audit Artifacts and Findings Backlog

**Files:**
- Create: `docs/security/bitcoin-secret-engine-threat-model.md`
- Create: `docs/security/bitcoin-secret-engine-dependency-assumptions.md`
- Create: `docs/security/bitcoin-secret-engine-abuse-matrix.md`
- Create: `docs/security/bitcoin-secret-engine-findings.md`

- [ ] **Step 1: Write the threat model document**

```markdown
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
```

- [ ] **Step 2: Write the dependency assumption register and abuse matrix**

```markdown
# Bitcoin Secret Engine Dependency Assumptions

## Vault
- `put_sealed` applies seal-wrap semantics to `wallets/{name}/secrets`
- Storage read-after-write consistency is sufficient for single-process request handling

## BDK
- `Wallet::create(...).create_wallet_no_persist()` does not persist secrets outside the plugin process
- `Wallet::sign` only signs inputs controlled by the loaded descriptors

## bitcoin
- PSBT parsing rejects structurally invalid inputs before signing
- Transaction serialization preserves consensus-critical fields
```

```markdown
# Bitcoin Secret Engine Abuse Matrix

| Case | Surface | Expected Result | Evidence | Follow-up |
| --- | --- | --- | --- | --- |
| Malformed JSON body | Router | Rejected with `InvalidRequest` | `tests/security_router_fail_closed.rs` | None |
| Unknown keychain | `keys/derive` | Rejected with `InvalidRequest` | `tests/security_key_boundary.rs` | None |
| Oversized PSBT combine batch | `psbt/combine` | Rejected before deserialization loop completes | `tests/security_psbt_abuse.rs` | Tune limit if needed |
| Concurrent address allocation | `addresses/new` | Unique sequential indices | `tests/security_state_integrity.rs` | Watch for multi-process gaps |
```

- [ ] **Step 3: Write the findings and remediation backlog template**

```markdown
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
```

- [ ] **Step 4: Verify the documents and run the full security suite**

Run: `rg "^## " docs/security/bitcoin-secret-engine-threat-model.md docs/security/bitcoin-secret-engine-dependency-assumptions.md docs/security/bitcoin-secret-engine-findings.md && cargo test --test security_router_fail_closed -- --nocapture && cargo test --test security_key_boundary -- --nocapture && cargo test --test security_psbt_abuse -- --nocapture && cargo test --test security_state_integrity -- --nocapture`
Expected: Heading check prints the expected sections; all four security test crates PASS.

- [ ] **Step 5: Commit the audit artifacts**

```bash
git add docs/security/bitcoin-secret-engine-threat-model.md docs/security/bitcoin-secret-engine-dependency-assumptions.md docs/security/bitcoin-secret-engine-abuse-matrix.md docs/security/bitcoin-secret-engine-findings.md
git commit -m "docs: record bitcoin secret engine audit artifacts"
```

## Self-Review

- Spec coverage: this plan covers threat model, invariants, dependency assumptions, abuse matrix, findings backlog, request-boundary review, derivation-boundary review, PSBT abuse review, and state-integrity testing.
- Placeholder scan: no `TBD`, `TODO`, or deferred implementation markers remain in the plan steps.
- Type consistency: the shared test harness uses the existing `Storage`, `Router`, `PbRequest`, and handler interfaces already present in the repository; new wallet locking is isolated to `src/wallet/locks.rs` and consumed through `WalletManager::next_external_address`.
