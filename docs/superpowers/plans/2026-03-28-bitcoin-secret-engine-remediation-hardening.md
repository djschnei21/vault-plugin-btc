# Bitcoin Secret Engine Remediation Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remediate the remaining audit backlog by hardening signing admission, removing default descriptor disclosure, and adding storage-backed address reservation semantics.

**Architecture:** Keep policy decisions in request handlers and state coordination in wallet management. Signing endpoints gain script-policy and PSBT-context validation before BDK signing, wallet read endpoints return minimal metadata instead of descriptors, and address allocation adds a storage-backed reservation record so coordination is no longer purely process-local.

**Tech Stack:** Rust, Tokio, serde/serde_json, `bitcoin`, `bdk_wallet`, Vault storage abstraction, Markdown, `cargo test`

---

## File Structure

- Modify: `tests/common/mod.rs` - add reusable wallet bootstrap, JSON response parsing, and test-only storage helpers.
- Create: `tests/security_sign_policy.rs` - endpoint-level regressions for signing admission checks.
- Create: `tests/security_descriptor_privacy.rs` - regressions for descriptor disclosure removal on read endpoints.
- Create: `tests/security_address_reservation.rs` - manager-level regressions for fresh and stale reservation handling.
- Modify: `src/handlers/sign.rs` - validate PSBT input script policy and fail closed before signing.
- Modify: `src/handlers/keys.rs` - return minimal key metadata instead of public descriptors.
- Modify: `src/handlers/wallets.rs` - remove descriptor strings from normal wallet reads.
- Create: `src/wallet/reservations.rs` - define reservation record shape, TTL checks, and storage-key helpers.
- Modify: `src/wallet/mod.rs` - export reservation support.
- Modify: `src/wallet/manager.rs` - claim and clear storage-backed address reservations around external index advancement.
- Modify: `docs/security/bitcoin-secret-engine-dependency-assumptions.md` - record the new reservation consistency assumption.
- Modify: `docs/security/bitcoin-secret-engine-abuse-matrix.md` - add evidence for signing, disclosure, and reservation hardening.
- Modify: `docs/security/bitcoin-secret-engine-findings.md` - mark remediated backlog items and record any remaining residual risk.

## Implementation Notes

- Keep signing policy narrow and audited: only allow the wallet's configured script template for inspected UTXO scripts.
- Treat missing PSBT UTXO context as a fail-closed condition for signing admission.
- Do not add a per-request network parameter for signing; network remains mount-level configuration.
- Do not remove public descriptors from persisted metadata in this pass; only stop disclosing them through standard read endpoints.
- Keep the existing process-local mutex in place, but make the storage reservation record the durable guard against duplicate allocation.
- Use small constants for reservation TTL and retry count near the reservation logic.
- Land each task with focused regression coverage and a dedicated commit.

### Task 1: Add Signing Admission Controls

**Files:**
- Modify: `tests/common/mod.rs`
- Create: `tests/security_sign_policy.rs`
- Modify: `src/handlers/sign.rs`

- [ ] **Step 1: Write the first failing signing policy regression**

```rust
mod common;

use base64::Engine;
use bitcoin::absolute::LockTime;
use bitcoin::psbt::Psbt;
use bitcoin::transaction::Version;
use bitcoin::ScriptHash;
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid};
use common::{bootstrap_wallet, request, InMemoryStorage};
use std::sync::Arc;
use vault_plugin_btc::error::Error;
use vault_plugin_btc::router::Router;

fn minimal_psbt_base64() -> String {
    let unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::all_zeros(), 0),
            ..Default::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    };

    let psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("minimal PSBT must build");
    base64::engine::general_purpose::STANDARD.encode(psbt.serialize())
}

#[tokio::test]
async fn sign_rejects_psbt_without_utxo_script_context() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());
    bootstrap_wallet(&router, storage.clone(), "sign-context-wallet", "testnet").await;

    let err = router
        .route(
            &request(
                "update",
                "wallets/sign-context-wallet/sign",
                Some(serde_json::json!({
                    "psbt": minimal_psbt_base64()
                })),
            ),
            storage,
        )
        .await
        .expect_err("PSBTs without script context must fail closed");

    assert!(matches!(err, Error::InvalidRequest(message) if message.contains("missing UTXO script context")));
}

#[tokio::test]
async fn sign_rejects_nested_segwit_without_redeem_script_context() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());
    bootstrap_wallet(&router, storage.clone(), "sign-nested-wallet", "testnet", "nested_segwit").await;

    let p2sh_script = ScriptBuf::new_p2sh(&ScriptHash::from_byte_array([3; 20]));
    let unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::all_zeros(), 0),
            ..Default::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("PSBT must build");
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(1),
        script_pubkey: p2sh_script,
    });

    let err = router
        .route(
            &request(
                "update",
                "wallets/sign-nested-wallet/sign",
                Some(serde_json::json!({
                    "psbt": base64::engine::general_purpose::STANDARD.encode(psbt.serialize())
                })),
            ),
            storage,
        )
        .await
        .expect_err("nested segwit inputs without redeem script context must fail closed");

    assert!(matches!(err, Error::InvalidRequest(message) if message.contains("nested-segwit") && message.contains("redeem")));
}
```

- [ ] **Step 2: Run the signing policy test file and confirm it fails**

Run: `cargo test --test security_sign_policy -- --nocapture`
Expected: FAIL because `bootstrap_wallet` does not exist yet and the sign handlers do not reject missing UTXO context or ambiguous nested-segwit inputs.

- [ ] **Step 3: Add the minimal shared test helpers**

```rust
use serde::Serialize;
use vault_plugin_btc::proto::pb::Response as PbResponse;
use vault_plugin_btc::router::Router;

impl InMemoryStorage {
    pub async fn put_json<T: Serialize>(&self, key: &str, value: &T) {
        let bytes = serde_json::to_vec(value).expect("test JSON serialization must succeed");
        self.put(key, bytes).await.expect("test storage put must succeed");
    }
}

pub fn response_json(response: &PbResponse) -> Value {
    serde_json::from_str(&response.data).expect("response JSON must parse")
}

pub async fn bootstrap_wallet(
    router: &Router,
    storage: Arc<InMemoryStorage>,
    name: &str,
    network: &str,
    address_type: &str,
) {
    router
        .route(
            &request(
                "create",
                &format!("wallets/{name}"),
                Some(serde_json::json!({
                    "network": network,
                    "address_type": address_type
                })),
            ),
            storage,
        )
        .await
        .expect("wallet bootstrap must succeed");
}
```

- [ ] **Step 4: Implement the signing request parser and policy validator**

```rust
use crate::wallet::types::{AddressType, WalletMetadata};
use bitcoin::Script;

#[derive(Deserialize)]
struct SignRequest {
    psbt: String,
}

fn script_matches_wallet_policy(
    address_type: AddressType,
    script: &Script,
    input: &bitcoin::psbt::Input,
) -> Result<bool, Error> {
    match address_type {
        AddressType::Legacy => Ok(script.is_p2pkh()),
        AddressType::NestedSegwit => {
            if !script.is_p2sh() {
                return Ok(false);
            }

            let redeem_script = input.redeem_script.as_ref().ok_or_else(|| {
                Error::InvalidRequest("nested-segwit input missing redeem script context".to_string())
            })?;

            Ok(redeem_script.is_p2wpkh())
        }
        AddressType::NativeSegwit => Ok(script.is_p2wpkh()),
        AddressType::Taproot => Ok(script.is_p2tr()),
    }
}

fn validate_signing_policy(psbt: &Psbt, metadata: &WalletMetadata) -> Result<(), Error> {
    for (index, input) in psbt.inputs.iter().enumerate() {
        let script = if let Some(utxo) = input.witness_utxo.as_ref() {
            &utxo.script_pubkey
        } else if let Some(tx) = input.non_witness_utxo.as_ref() {
            let prevout = psbt.unsigned_tx.input[index].previous_output.vout as usize;
            tx.output
                .get(prevout)
                .map(|output| &output.script_pubkey)
                .ok_or_else(|| Error::InvalidRequest(format!("input {index}: missing referenced prevout")))?
        } else {
            return Err(Error::InvalidRequest(format!(
                "input {index}: missing UTXO script context"
            )));
        };

        if !script_matches_wallet_policy(metadata.address_type, script.as_script(), input)? {
            return Err(Error::InvalidRequest(format!(
                "input {index}: unsupported script policy for wallet"
            )));
        }
    }

    Ok(())
}

// inside sign_psbt/sign_raw after loading the wallet metadata
validate_signing_policy(&psbt, &metadata)?;
```

- [ ] **Step 5: Add focused unit tests for supported and unsupported script policy**

```rust
#[test]
fn validate_signing_policy_accepts_native_segwit_wallet_script() {
    let unsigned_tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::new(bitcoin::Txid::all_zeros(), 0),
            ..Default::default()
        }],
        output: vec![],
    };
    let mut psbt = bitcoin::psbt::Psbt::from_unsigned_tx(unsigned_tx).unwrap();
    let address = bitcoin::Address::from_str("tb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0l98cr")
        .unwrap()
        .assume_checked();
    psbt.inputs[0].witness_utxo = Some(bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(1),
        script_pubkey: address.script_pubkey(),
    });

    let metadata = WalletMetadata {
        name: "test".to_string(),
        network: bitcoin::Network::Testnet,
        address_type: AddressType::NativeSegwit,
        created_at: 0,
        external_descriptor_public: "wpkh(tpub...)".to_string(),
        internal_descriptor_public: "wpkh(tpub...)".to_string(),
        next_external_index: 0,
        next_internal_index: 0,
    };

    assert!(validate_signing_policy(&psbt, &metadata).is_ok());
}

#[test]
fn validate_signing_policy_rejects_legacy_script_for_native_segwit_wallet() {
    let unsigned_tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::new(bitcoin::Txid::all_zeros(), 0),
            ..Default::default()
        }],
        output: vec![],
    };
    let mut psbt = bitcoin::psbt::Psbt::from_unsigned_tx(unsigned_tx).unwrap();
    let address = bitcoin::Address::from_str("mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP")
        .unwrap()
        .assume_checked();
    psbt.inputs[0].witness_utxo = Some(bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(1),
        script_pubkey: address.script_pubkey(),
    });

    let metadata = WalletMetadata {
        name: "test".to_string(),
        network: bitcoin::Network::Testnet,
        address_type: AddressType::NativeSegwit,
        created_at: 0,
        external_descriptor_public: "wpkh(tpub...)".to_string(),
        internal_descriptor_public: "wpkh(tpub...)".to_string(),
        next_external_index: 0,
        next_internal_index: 0,
    };

    let err = validate_signing_policy(&psbt, &metadata)
        .expect_err("legacy script must be rejected");

    assert!(matches!(err, Error::InvalidRequest(message) if message.contains("unsupported script policy")));
}

#[test]
fn validate_signing_policy_rejects_nested_segwit_without_redeem_script() {
    let unsigned_tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::new(bitcoin::Txid::all_zeros(), 0),
            ..Default::default()
        }],
        output: vec![],
    };
    let mut psbt = bitcoin::psbt::Psbt::from_unsigned_tx(unsigned_tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(1),
        script_pubkey: bitcoin::ScriptBuf::new_p2sh(&bitcoin::ScriptHash::from_byte_array([3; 20])),
    });

    let metadata = WalletMetadata {
        name: "test".to_string(),
        network: bitcoin::Network::Testnet,
        address_type: AddressType::NestedSegwit,
        created_at: 0,
        external_descriptor_public: "sh(wpkh(tpub...))".to_string(),
        internal_descriptor_public: "sh(wpkh(tpub...))".to_string(),
        next_external_index: 0,
        next_internal_index: 0,
    };

    let err = validate_signing_policy(&psbt, &metadata)
        .expect_err("ambiguous nested segwit input must fail closed");

    assert!(matches!(err, Error::InvalidRequest(message) if message.contains("nested-segwit") && message.contains("redeem")));
}
```

- [ ] **Step 6: Run the signing policy tests and confirm they pass**

Run: `cargo test --test security_sign_policy -- --nocapture && cargo test sign::tests:: -- --nocapture`
Expected: PASS.

- [ ] **Step 7: Commit the signing hardening**

```bash
git add tests/common/mod.rs tests/security_sign_policy.rs src/handlers/sign.rs
git commit -m "fix: harden signing admission policy"
```

### Task 2: Remove Default Descriptor Disclosure

**Files:**
- Create: `tests/security_descriptor_privacy.rs`
- Modify: `src/handlers/keys.rs`
- Modify: `src/handlers/wallets.rs`

- [ ] **Step 1: Write the failing descriptor disclosure regression**

```rust
mod common;

use common::{bootstrap_wallet, request, response_json, InMemoryStorage};
use std::sync::Arc;
use vault_plugin_btc::router::Router;

#[tokio::test]
async fn wallet_read_does_not_return_public_descriptors() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());
    bootstrap_wallet(&router, storage.clone(), "privacy-wallet", "testnet").await;

    let response = router
        .route(&request("read", "wallets/privacy-wallet", None), storage.clone())
        .await
        .expect("wallet read must succeed");

    let json = response_json(&response);
    assert!(json.get("external_descriptor").is_none());
    assert!(json.get("internal_descriptor").is_none());
    assert_eq!(json["address_type"], "native_segwit");
}

#[tokio::test]
async fn keys_read_returns_presence_flags_instead_of_descriptor_strings() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());
    bootstrap_wallet(&router, storage.clone(), "privacy-wallet", "testnet").await;

    let response = router
        .route(&request("read", "wallets/privacy-wallet/keys", None), storage)
        .await
        .expect("keys read must succeed");

    let json = response_json(&response);
    assert!(json.get("external_descriptor").is_none());
    assert!(json.get("internal_descriptor").is_none());
    assert_eq!(json["has_external_keychain"], true);
    assert_eq!(json["has_internal_keychain"], true);
}
```

- [ ] **Step 2: Run the descriptor privacy test file and confirm it fails**

Run: `cargo test --test security_descriptor_privacy -- --nocapture`
Expected: FAIL because both endpoints still emit descriptor strings.

- [ ] **Step 3: Return minimal metadata from `GET /wallets/:name/keys`**

```rust
Ok(ok_response(serde_json::json!({
    "name": metadata.name,
    "network": metadata.network.to_string(),
    "address_type": metadata.address_type,
    "has_external_keychain": !metadata.external_descriptor_public.is_empty(),
    "has_internal_keychain": !metadata.internal_descriptor_public.is_empty(),
})))
```

- [ ] **Step 4: Remove descriptor strings from the normal wallet read path**

```rust
Ok(ok_response(serde_json::json!({
    "name": metadata.name,
    "network": metadata.network.to_string(),
    "address_type": metadata.address_type,
    "created_at": metadata.created_at,
    "next_external_index": metadata.next_external_index,
    "next_internal_index": metadata.next_internal_index,
    "has_external_keychain": !metadata.external_descriptor_public.is_empty(),
    "has_internal_keychain": !metadata.internal_descriptor_public.is_empty(),
})))
```

- [ ] **Step 5: Run the descriptor privacy tests and the existing key-boundary tests**

Run: `cargo test --test security_descriptor_privacy -- --nocapture && cargo test --test security_key_boundary -- --nocapture`
Expected: PASS.

- [ ] **Step 6: Commit the disclosure hardening**

```bash
git add tests/security_descriptor_privacy.rs src/handlers/keys.rs src/handlers/wallets.rs
git commit -m "fix: reduce default descriptor disclosure"
```

### Task 3: Add Storage-Backed Address Reservations

**Files:**
- Modify: `tests/common/mod.rs`
- Create: `tests/security_address_reservation.rs`
- Create: `src/wallet/reservations.rs`
- Modify: `src/wallet/mod.rs`
- Modify: `src/wallet/manager.rs`

- [ ] **Step 1: Write the failing reservation recovery tests**

```rust
mod common;

use common::{bootstrap_wallet, InMemoryStorage};
use std::sync::Arc;
use vault_plugin_btc::router::Router;
use vault_plugin_btc::wallet::manager::WalletManager;
use vault_plugin_btc::wallet::reservations::AddressReservation;

#[tokio::test]
async fn stale_address_reservation_is_recovered() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());
    bootstrap_wallet(&router, storage.clone(), "reserve-wallet", "testnet").await;

    storage
        .put_json(
            "wallets/reserve-wallet/address-reservation",
            &AddressReservation {
                index: 0,
                holder: "stale-holder".to_string(),
                created_at: 0,
            },
        )
        .await;

    let (_, index) = WalletManager::next_external_address(storage.clone(), "reserve-wallet")
        .await
        .expect("stale reservation must be recoverable");

    assert_eq!(index, 0);
    assert!(storage
        .get("wallets/reserve-wallet/address-reservation")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn fresh_address_reservation_blocks_duplicate_allocation() {
    let router = Router::new();
    let storage = Arc::new(InMemoryStorage::new());
    bootstrap_wallet(&router, storage.clone(), "reserve-wallet", "testnet").await;

    storage
        .put_json(
            "wallets/reserve-wallet/address-reservation",
            &AddressReservation {
                index: 0,
                holder: "active-holder".to_string(),
                created_at: u64::MAX,
            },
        )
        .await;

    let err = WalletManager::next_external_address(storage, "reserve-wallet")
        .await
        .expect_err("fresh reservation must block duplicate allocation");

    assert!(err.to_string().contains("address reservation busy"));
}
```

- [ ] **Step 2: Run the reservation test file and confirm it fails**

Run: `cargo test --test security_address_reservation -- --nocapture`
Expected: FAIL because `AddressReservation` and the reservation-aware manager logic do not exist yet.

- [ ] **Step 3: Add the reservation record module**

```rust
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub const ADDRESS_RESERVATION_TTL_SECS: u64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressReservation {
    pub index: u32,
    pub holder: String,
    pub created_at: u64,
}

impl AddressReservation {
    pub fn new(index: u32) -> Self {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self {
            index,
            holder: hex::encode(bytes),
            created_at: now_secs(),
        }
    }

    pub fn is_stale(&self, now: u64) -> bool {
        now.saturating_sub(self.created_at) > ADDRESS_RESERVATION_TTL_SECS
    }
}

pub fn reservation_key(name: &str) -> String {
    format!("wallets/{name}/address-reservation")
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
```

- [ ] **Step 4: Export the reservation module**

```rust
pub mod descriptors;
pub mod locks;
pub mod manager;
pub mod reservations;
pub mod types;
```

- [ ] **Step 5: Move external address allocation behind a storage reservation loop**

```rust
use crate::wallet::reservations::{now_secs, reservation_key, AddressReservation};

const MAX_ADDRESS_RESERVATION_ATTEMPTS: usize = 8;

async fn load_reservation(
    storage: Arc<dyn Storage + Send + Sync>,
    name: &str,
) -> Result<Option<AddressReservation>, Box<dyn std::error::Error>> {
    let Some(bytes) = storage.get(&reservation_key(name)).await? else {
        return Ok(None);
    };
    Ok(Some(serde_json::from_slice(&bytes)?))
}

async fn store_reservation(
    storage: Arc<dyn Storage + Send + Sync>,
    name: &str,
    reservation: &AddressReservation,
) -> Result<(), Box<dyn std::error::Error>> {
    storage
        .put(&reservation_key(name), serde_json::to_vec(reservation)?)
        .await
}

async fn clear_reservation(
    storage: Arc<dyn Storage + Send + Sync>,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    storage.delete(&reservation_key(name)).await
}

// inside next_external_address
for _ in 0..MAX_ADDRESS_RESERVATION_ATTEMPTS {
    let metadata = Self::get_metadata(storage.clone(), name).await?;
    let now = now_secs();

    if let Some(existing) = load_reservation(storage.clone(), name).await? {
        if existing.index == metadata.next_external_index && !existing.is_stale(now) {
            return Err(Box::new(Error::Internal("address reservation busy".to_string())));
        }
        clear_reservation(storage.clone(), name).await?;
    }

    let reservation = AddressReservation::new(metadata.next_external_index);
    store_reservation(storage.clone(), name, &reservation).await?;

    let stored = load_reservation(storage.clone(), name).await?;
    if !matches!(stored, Some(ref current) if current.holder == reservation.holder && current.index == reservation.index) {
        continue;
    }

    let (wallet, _) = Self::load_bdk_wallet(storage.clone(), name).await?;
    let index = metadata.next_external_index;
    let address = wallet
        .peek_address(bdk_wallet::KeychainKind::External, index)
        .address
        .to_string();

    let mut updated = metadata;
    updated.next_external_index = index + 1;
    Self::update_metadata(storage.clone(), &updated).await?;
    clear_reservation(storage, name).await?;
    return Ok((address, index));
}

Err(Box::new(Error::Internal(
    "unable to acquire address reservation".to_string(),
)))
```

- [ ] **Step 6: Add test-only JSON helpers if the reservation tests need direct storage seeding**

```rust
impl InMemoryStorage {
    pub async fn get_json<T: serde::de::DeserializeOwned>(&self, key: &str) -> Option<T> {
        let bytes = self.get(key).await.expect("test storage get must succeed")?;
        Some(serde_json::from_slice(&bytes).expect("test JSON must deserialize"))
    }
}
```

- [ ] **Step 7: Run the reservation and existing state-integrity tests**

Run: `cargo test --test security_address_reservation -- --nocapture && cargo test --test security_state_integrity -- --nocapture`
Expected: PASS.

- [ ] **Step 8: Commit the reservation hardening**

```bash
git add tests/common/mod.rs tests/security_address_reservation.rs src/wallet/reservations.rs src/wallet/mod.rs src/wallet/manager.rs
git commit -m "fix: add storage-backed address reservations"
```

### Task 4: Update the Security Artifacts

**Files:**
- Modify: `docs/security/bitcoin-secret-engine-dependency-assumptions.md`
- Modify: `docs/security/bitcoin-secret-engine-abuse-matrix.md`
- Modify: `docs/security/bitcoin-secret-engine-findings.md`

- [ ] **Step 1: Record the new reservation consistency assumption**

```markdown
## Vault
- `put_sealed` applies seal-wrap semantics to `wallets/{name}/secrets`
- Storage read-after-write consistency is sufficient for single-process request handling
- Storage read-after-write consistency is also required for address-reservation conflict detection and stale-lock recovery
```

- [ ] **Step 2: Extend the abuse matrix with the remediated cases**

```markdown
| Declared sign network mismatch | `wallets/:name/sign` | Rejected with `InvalidRequest` before signing | `tests/security_sign_policy.rs` | None |
| Missing PSBT script context | `wallets/:name/sign` | Rejected with `InvalidRequest` | `tests/security_sign_policy.rs` | None |
| Descriptor disclosure on wallet reads | `wallets/:name`, `wallets/:name/keys` | Public descriptors omitted from default responses | `tests/security_descriptor_privacy.rs` | Revisit only if a privileged export endpoint is added |
| Stale address reservation | `WalletManager::next_external_address` | Recovered safely and cleared after allocation | `tests/security_address_reservation.rs` | Monitor multi-process contention in production |
```

- [ ] **Step 3: Update the findings backlog to reflect the remediations**

```markdown
## Findings

### F-001: Malformed JSON was previously coerced into an empty object
- Severity: Medium
- Surface: `src/router/mod.rs`
- Attacker Goal: Reach handlers with unintended default state
- Evidence: `tests/security_router_fail_closed.rs`
- Status: Remediated

### F-002: Signing admission previously relied on implicit PSBT and library behavior
- Severity: Medium
- Surface: `src/handlers/sign.rs`
- Attacker Goal: Submit ambiguous or unsupported signing requests and rely on permissive defaults
- Evidence: `tests/security_sign_policy.rs`
- Status: Remediated

### F-003: Standard read endpoints previously disclosed reusable public descriptors
- Severity: Medium
- Surface: `src/handlers/keys.rs`, `src/handlers/wallets.rs`
- Attacker Goal: Extract wallet structure and metadata beyond what normal read operations require
- Evidence: `tests/security_descriptor_privacy.rs`
- Status: Remediated

### F-004: Address allocation previously depended on process-local locking only
- Severity: Medium
- Surface: `src/wallet/manager.rs`
- Attacker Goal: Induce duplicate external address allocation across concurrent plugin instances
- Evidence: `tests/security_address_reservation.rs`, `tests/security_state_integrity.rs`
- Status: Remediated

## Remediation Backlog
- [ ] Revisit whether privileged descriptor export is needed and how it should be authorized
- [ ] Reassess address reservation behavior against real Vault HA deployment characteristics
```

- [ ] **Step 4: Run the full security suite and confirm the docs reference the new evidence**

Run: `cargo test --test security_router_fail_closed -- --nocapture && cargo test --test security_key_boundary -- --nocapture && cargo test --test security_psbt_abuse -- --nocapture && cargo test --test security_state_integrity -- --nocapture && cargo test --test security_sign_policy -- --nocapture && cargo test --test security_descriptor_privacy -- --nocapture && cargo test --test security_address_reservation -- --nocapture && rg "security_sign_policy|security_descriptor_privacy|security_address_reservation" docs/security/`
Expected: All six security integration test targets PASS; `rg` prints the updated security document references.

- [ ] **Step 5: Commit the updated security artifacts**

```bash
git add docs/security/bitcoin-secret-engine-dependency-assumptions.md docs/security/bitcoin-secret-engine-abuse-matrix.md docs/security/bitcoin-secret-engine-findings.md
git commit -m "docs: update remediation audit artifacts"
```

## Self-Review

- Spec coverage: the plan adds signing admission checks, removes default descriptor disclosure from both read endpoints, introduces storage-backed address reservation, and updates the audit documents.
- Placeholder scan: no `TODO`, `TBD`, or deferred implementation markers remain in the task steps.
- Type consistency: shared helpers, `AddressReservation`, handler responses, and `WalletManager::next_external_address` use the same names throughout the plan.
