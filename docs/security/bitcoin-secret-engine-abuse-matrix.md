# Bitcoin Secret Engine Abuse Matrix

| Case | Surface | Expected Result | Evidence | Follow-up |
| --- | --- | --- | --- | --- |
| Malformed JSON body | Router | Rejected with `InvalidRequest` | `tests/security_router_fail_closed.rs` | None |
| Unknown keychain | `keys/derive` | Rejected with `InvalidRequest` | `tests/security_key_boundary.rs` | None |
| Oversized PSBT combine batch | `psbt/combine` | Rejected before deserialization loop completes | `tests/security_psbt_abuse.rs` | Tune limit if needed |
| Concurrent address allocation | `addresses/new` | Unique sequential indices | `tests/security_state_integrity.rs` | Watch for multi-process gaps |
