# Bitcoin Secret Engine Abuse Matrix

| Case | Surface | Expected Result | Evidence | Follow-up |
| --- | --- | --- | --- | --- |
| Malformed JSON body | Router | Rejected with `InvalidRequest` | `tests/security_router_fail_closed.rs` | None |
| Unknown keychain | `keys/derive` | Rejected with `InvalidRequest` | `tests/security_key_boundary.rs` | None |
| Oversized PSBT combine batch | `psbt/combine` | Rejected before deserialization loop completes | `tests/security_psbt_abuse.rs` | Tune limit if needed |
| Missing PSBT UTXO or redeem-script context | `sign` | Rejected fail-closed before signing | `tests/security_sign_policy.rs` (`sign_rejects_psbt_without_utxo_script_context`, `sign_rejects_nested_segwit_without_redeem_script_context`, `sign_rejects_nested_segwit_with_mismatched_redeem_script`) | Continue broader sign policy review outside the approved remediation scope |
| Default wallet read descriptor disclosure | `GET /wallets/:name` | Returns minimal metadata without descriptors | `tests/security_descriptor_privacy.rs` (`wallet_read_omits_descriptors_and_returns_minimal_metadata`) | Re-review only if new export surfaces are added |
| Default key read descriptor disclosure | `GET /wallets/:name/keys` | Returns minimal metadata without descriptors | `tests/security_descriptor_privacy.rs` (`keys_read_omits_descriptors_and_returns_presence_flags`) | Re-review only if key-read response shape expands |
| Concurrent address allocation | `addresses/new` | Unique sequential indices | `tests/security_state_integrity.rs` | Monitor shared-storage behavior alongside reservation assumptions |
| Stale address reservation | `addresses/new` | Stale reservation is reclaimed, cleared, and index advances once | `tests/security_address_reservation.rs` (`stale_reservation_is_recovered_and_cleared`) | Depends on storage consistency assumptions documented in `docs/security/bitcoin-secret-engine-dependency-assumptions.md` |
| Fresh address reservation conflict | `addresses/new` | Allocation is blocked while a fresh reservation exists | `tests/security_address_reservation.rs` (`fresh_reservation_blocks_duplicate_allocation`, `fresh_reservation_at_different_index_still_blocks_allocation`) | Fresh-reservation denial remains possible until the reservation ages out |
