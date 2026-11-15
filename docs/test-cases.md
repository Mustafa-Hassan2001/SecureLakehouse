# Test cases

Run from the project root (`python -m pytest`): **107 tests** (80 functions; the
policy matrix is parametrised over 4 roles × 6 columns, and the unknown-column
test over 4 roles). All tests pass on Python 3.10.20 and 3.13 with PySpark 4.3.0.
They also pass inside a network namespace with only loopback up (Spark's
Python↔JVM bridge needs loopback), which shows the suite needs no network or
external services.

Tests use 1,000 PBKDF2 iterations to stay fast. The iteration count is a keystore
parameter, so no code path changes.

## `tests/test_crypto.py`: envelope encryption

| Test | What it proves |
|---|---|
| `test_roundtrip` | encrypt → decrypt returns the original value; the first key is version 1 |
| `test_encryption_is_randomized` | the same plaintext yields different ciphertexts (no equality leakage) |
| `test_none_passes_through` | NULLs stay NULL (a documented trade-off) |
| `test_reopen_with_same_passphrase_decrypts` | KEK re-derivation from the passphrase and the stored salt/iterations works across processes |
| `test_wrong_passphrase_cannot_unwrap` | a wrong passphrase raises `PermissionError` |
| `test_dek_unwrap_fails_if_kek_check_bypassed` | even with a forged `kek_check`, the DEKs cannot be unwrapped (defence in depth) |
| `test_keystore_contains_no_plaintext_key_material` | no DEK (in base64 or hex form) and no passphrase appears in the keystore file |
| `test_rotation_keeps_old_ciphertext_readable` | after rotation, old ciphertext decrypts with v1, new writes use v2, and the versions are different keys |
| `test_rotation_survives_reopen` | the active version and old versions persist on disk |
| `test_different_columns_get_different_keys` | each column has its own DEK; ciphertext from one column won't decrypt as another |
| `test_export_without_create_does_not_mint` | the read path never creates keys |
| `test_pure_primitives_match_key_manager` | the executor-side pure functions are byte-compatible with the KeyManager |
| `test_tampered_ciphertext_is_rejected` | Fernet authentication: a flipped bit raises `InvalidToken` |
| `test_key_manager_refuses_to_be_pickled` | guardrail: a KeyManager cannot be captured in a UDF closure |
| `test_key_material_repr_hides_key_bytes` | key bytes never appear in `repr()`, logs or tracebacks |

## `tests/test_policy.py`: RBAC + ABAC

| Test | What it proves |
|---|---|
| `test_role_column_matrix` (24 cases) | ALLOW/MASK/DENY for every role × column combination matches the documented policy table, and every decision has a reason |
| `test_unknown_column_default_denies` (4 cases) | a column with no rule → DENY for every role |
| `test_physical_ciphertext_column_is_default_denied` | even admin cannot request `ssn_enc` directly |
| `test_unknown_role_default_denies` | an unrecognised role → DENY |
| `test_empty_policy_denies_everything` | forgetting every rule fails safe |
| `test_row_cap_triggers_deny` | at the cap → ALLOW; cap + 1 → DENY with a reason naming the cap |
| `test_row_cap_does_not_apply_to_privileged_role` | admin bypasses the ABAC cap |
| `test_row_cap_does_not_apply_to_masked_values` | caps only guard plaintext reveals |
| `test_department_scoping_produces_row_filter` | analyst + salary → ALLOW with `department == 'Engineering'` |
| `test_department_scoping_follows_caller_attribute` | the filter value comes from the subject's attribute (ABAC) |
| `test_no_row_filter_for_admin_or_unscoped_columns` | no spurious filters for admin, unscoped columns or masked access |
| `test_rule_cannot_both_allow_and_mask_a_role` | contradictory rules are rejected at construction |

## `tests/test_audit.py`: hash chain

| Test | What it proves |
|---|---|
| `test_empty_log_is_valid` | an empty log verifies as intact; the head hash is the genesis hash |
| `test_fresh_log_verifies_intact` | a freshly written log verifies |
| `test_entries_are_chained` | `prev_hash` links and contiguous `seq` |
| `test_edit_of_past_entry_detected_with_correct_seq` | editing entry 2 → reported as "seq=2 … modified" |
| `test_edit_with_recomputed_hash_detected_at_next_entry` | recomputing the edited entry's hash moves detection to seq+1 |
| `test_deleting_middle_entry_detected` | deleting entry 2 → reported at position 2 (found seq=3) |
| `test_reordering_entries_detected` | swapping entries breaks the chain |
| `test_corrupted_json_detected` | a garbage line → "corrupted" |
| `test_appending_continues_chain_across_instances` | a reopened log continues the sequence and the chain |
| `test_invalid_outcome_rejected` | only served/masked/denied/error are accepted |
| `test_injected_clock_is_used` | the simulated clock drives timestamps (used by the demo) |
| `test_tail_truncation_is_not_detected_without_anchor` | **documents a limitation**: dropping the newest entry passes `verify()`, but the head hash differs from an anchored copy |

## `tests/test_anomaly.py`: insider-threat rules

| Test | What it proves |
|---|---|
| `test_volume_spike_detected` | baseline ~4 rows → 500 is flagged HIGH, with numbers in the reason |
| `test_volume_spike_not_triggered_on_consistent_usage` | 10–13 rows of normal variation → no alert |
| `test_volume_spike_zero_variance_baseline_needs_meaningful_jump` | σ = 0: a 4 → 5 change does not fire (the 2× floor) |
| `test_volume_spike_needs_minimum_history` | no verdict without a baseline |
| `test_volume_baseline_is_per_user` | one user's volume doesn't set another's baseline |
| `test_first_ever_sensitive_access_not_flagged` | a user's first sensitive access → no alert |
| `test_columns_in_same_event_are_not_prior_for_each_other` | columns requested together are not each other's history |
| `test_next_new_sensitive_column_is_flagged` | the *next* new sensitive column is flagged, naming the prior columns |
| `test_new_ssn_access_is_high_severity_even_if_denied` | attempting a new high-risk column counts, and is HIGH |
| `test_non_sensitive_columns_never_trigger_new_column` | plaintext columns are ignored |
| `test_deny_burst_detected` | 3 denials in a row → HIGH alert at the third |
| `test_deny_burst_alerts_once_per_burst` | 5 consecutive denials → one alert, not three |
| `test_spread_out_denials_do_not_trigger_burst` | denials outside the sequence window don't accumulate |
| `test_deny_burst_is_per_user` | three users with one denial each → no alert |
| `test_off_hours_detected` | 23:40 sensitive read with rows returned → MEDIUM |
| `test_off_hours_weekend_detected` | Saturday noon → flagged "on a weekend" |
| `test_off_hours_masked_or_denied_is_low_severity` | no plaintext returned → LOW |
| `test_business_hours_and_non_sensitive_not_flagged` | no false positives for daytime or non-sensitive access |
| `test_working_hours_boundaries` | 08:00 is inside, 19:00 is outside |
| `test_every_alert_is_explained_and_summarized` | all four rules fire in a combined scenario; every alert has a reason |
| `test_empty_trail_has_no_alerts` | trivial base case |

## `tests/test_spark_key_isolation.py`: the distributed-systems bug

| Test | What it proves |
|---|---|
| `test_naive_closure_corrupts_encryption` | **reproduces the bug.** A picklable KeyManager in a UDF over 8 partitions: the driver's object never gets a key, executors mint their own, and after the job some rows are undecryptable with the persisted key, with no error raised during the job |
| `test_broadcast_design_is_consistent` | the real design on the same data and partitioning: exactly one key version minted, 40/40 rows decrypt |

## `tests/test_end_to_end.py`: CSV → Parquet → gateway

| Test | What it proves |
|---|---|
| `test_no_plaintext_ssn_in_parquet_files_on_disk` | **central claim.** No SSN appears in the raw bytes of any lake file, or in any pyarrow-decoded value of any column of any Parquet file. The files are read directly, not through the gateway |
| `test_no_plaintext_of_any_sensitive_column_on_disk` | the same for names and emails; no logical sensitive column exists physically |
| `test_plaintext_scanner_positive_control` | the scanner *does* find SSNs in an unencrypted Parquet copy, so the check isn't vacuous (compressed pages are why it also decodes values) |
| `test_plaintext_columns_remain_queryable_plaintext` | `employee_id` and `department` are stored plaintext, by design |
| `test_admin_sees_real_values` | decryption round trip through Spark, including the int cast for salary |
| `test_different_roles_get_different_results` | the same query: admin 12 real rows, analyst 4 own-department rows, auditor 12 redacted rows, support denied |
| `test_any_denied_column_refuses_whole_query` | fail closed: no partial results |
| `test_row_cap_blocks_bulk_export` | 12 names > cap 5 → denied; scoped to 4 rows → served |
| `test_filter_on_sensitive_column_is_refused` | no `WHERE ssn = …` oracle, even for admin |
| `test_denied_query_still_produces_audit_entry` | a denied query writes one event, with decisions, `requested_row_count` 12 and `row_count` 0 |
| `test_every_query_writes_exactly_one_event_and_chain_stays_intact` | served/masked/denied → exactly 3 events, chain intact |
| `test_audit_log_never_contains_decrypted_values` | the audit log holds metadata only |
| `test_gateway_error_is_audited_and_fails_closed` | the lake vanishes → exception, plus one `error` audit event |
| `test_rotation_then_append_reads_both_key_versions` | rotate the ssn key, append rows: the lake holds `ssn_kv` ∈ {1, 2} and both decrypt |
| `test_wrong_passphrase_cannot_open_lakehouse` | the wiring layer surfaces `PermissionError` |

## `tests/test_cli.py`

| Test | What it proves |
|---|---|
| `test_parser_description` | the CLI description string is "SecureLakehouse CLI" |
| `test_audit_verify_intact_and_tampered` | exit 0 when intact; exit 4 with the broken seq after tampering |
| `test_detect_json` | `detect --json` emits machine-readable alerts |
| `test_detect_warns_on_tampered_log` | detection warns when the log it analyses has been edited |

## Verified outside pytest

| Check | How |
|---|---|
| The demo runs end to end, from the project root and from another directory | `python demo/run_demo.py`; `cd /tmp && python <repo>/demo/run_demo.py` (this caught the executor `PYTHONPATH` bug) |
| The CLI reproduces the demo's decisions and alerts | `python cli.py scenario && python cli.py detect`: the same 15 outcomes and the same 9 alerts |
| The dashboard boots and every button works | Streamlit `AppTest` clicks ingest, query, breach simulation, verify, tamper and verify; then a headless `streamlit run` returns HTTP 200 and a healthy `/_stcore/health`; then a headless Chromium session runs a query with 0 Streamlit exceptions and 0 JS errors |
