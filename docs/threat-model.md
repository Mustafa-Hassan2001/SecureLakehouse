# Threat model

## Assets
1. Sensitive cell values: `name`, `email`, `ssn`, `salary`.
2. Key material: the KEK (derived from a passphrase) and the per-column DEKs.
3. The integrity of the audit trail, which is the evidence base for detection and
   forensics.

## Trust assumptions
- The **driver process** and the **Spark executors** are trusted while a query
  runs. They hold unwrapped DEK bytes in memory.
- **Caller identity** (`Subject`: user, role, department) is supplied by a
  trusted identity provider. This project does **not** authenticate anyone.
- The **passphrase holder** (the operator) is trusted.

## Adversaries considered
| Adversary | Capability |
|---|---|
| A. Disk thief / storage-level reader | Can read every file in the lake directory, and possibly the keystore, but not the passphrase |
| B. Over-curious or compromised insider account | Valid credentials for a non-admin role; queries through the gateway |
| C. Log tamperer | Write access to the audit log file after the fact |
| D. Developer mistake | Ships stateful key objects to executors; forgets to write a policy rule |

## What IS defended, and how

| # | Threat | Defence | Evidence |
|---|---|---|---|
| 1 | (A) reads sensitive values from Parquet | Cell-level Fernet encryption before write; only ciphertext columns are stored | `test_no_plaintext_ssn_in_parquet_files_on_disk` scans raw bytes and every pyarrow-decoded value; a positive control shows the same scanner finds SSNs in an unencrypted copy |
| 2 | (A) steals keystore + lake | The keystore holds only DEKs wrapped under a PBKDF2-derived KEK (600k iterations, random salt); the passphrase is never stored | `test_keystore_contains_no_plaintext_key_material`, `test_wrong_passphrase_cannot_unwrap` |
| 3 | (A) tampers with a ciphertext | Fernet is authenticated (HMAC-SHA256), so decryption raises | `test_tampered_ciphertext_is_rejected` |
| 4 | (A) moves a ciphertext into another column | Separate DEK per column | `test_different_columns_get_different_keys` |
| 5 | Equal values linkable across rows | Randomized encryption (fresh IV) | `test_encryption_is_randomized` |
| 6 | (B) reads a column the role may not see | RBAC: DENY, and the whole query is refused (fail closed) | `test_any_denied_column_refuses_whole_query`, policy matrix tests |
| 7 | (B) asks for an unknown or physical column (`ssn_enc`) | Default-deny for columns without a rule | `test_unknown_column_default_denies`, `test_physical_ciphertext_column_is_default_denied` |
| 8 | (B) reads another department's salaries | ABAC row filter `department == subject.department` | `test_department_scoping_produces_row_filter`, `test_different_roles_get_different_results` |
| 9 | (B) bulk export | ABAC `max_rows_per_query` → DENY | `test_row_cap_blocks_bulk_export` |
| 10 | (B) infers values by filtering on them (`WHERE ssn = …`) | Filters only on plaintext columns the caller may read | `test_filter_on_sensitive_column_is_refused` |
| 11 | (B) reverses a mask | The mask is a constant; masked columns are never decrypted and their keys never shipped | `test_different_roles_get_different_results` (auditor) |
| 12 | (B) acts without leaving a trace | Exactly one audit event per query, including denied and error outcomes | `test_denied_query_still_produces_audit_entry`, `test_gateway_error_is_audited_and_fails_closed` |
| 13 | (B) probing, bulk pulls, new columns, night-time access | Four rule-based detectors over the audit trail | `tests/test_anomaly.py`, demo section 4 |
| 14 | (C) edits, deletes or reorders past audit entries | SHA-256 hash chain; `verify()` reports the first broken `seq` | `tests/test_audit.py`, demo section 5 |
| 15 | Audit log leaks data | Only metadata is logged, never values | `test_audit_log_never_contains_decrypted_values` |
| 16 | (D) a stateful KeyManager in a UDF causes per-task key minting and silent corruption | Keys resolved on the driver, bytes broadcast, pure UDFs; `KeyManager` refuses to pickle | `tests/test_spark_key_isolation.py`, `test_key_manager_refuses_to_be_pickled` |
| 17 | (D) a forgotten policy rule | Default-deny | `test_empty_policy_denies_everything` |
| 18 | Key rotation breaks old data | Versioned DEKs, `<col>_kv` per cell | `test_rotation_keeps_old_ciphertext_readable`, `test_rotation_then_append_reads_both_key_versions` |
| 19 | A crash mid-keystore-write bricks the lake | Atomic write (temp file, `fsync`, `os.replace`) | design (not fault-injection tested) |

## What is OUT of scope

These are deliberate omissions, and each would need real work in a production
system.

1. **Authentication is not implemented.** The gateway trusts the `Subject` it is
   given. In the CLI and the dashboard, anyone can type `--role admin`. A real
   deployment would take the identity from an IdP (OIDC/SAML or Kerberos) and
   never accept caller-asserted roles.
2. **Audit-log durability and anchoring are local-disk only.** The hash chain
   detects edits *relative to a trusted reference*. An attacker with write access
   who rewrites the **entire** chain, recomputing every hash, passes `verify()`.
   Truncating the newest entries is also undetectable (this is tested and
   documented in `test_tail_truncation_is_not_detected_without_anchor`). A real
   system would stream events to a write-once store (WORM/object lock, a separate
   logging account) and periodically anchor `head_hash()` externally, or use a
   keyed MAC or signatures with a key the writer cannot use to forge history.
3. **The KEK comes from a passphrase.** In production it would live in a
   KMS/HSM, and DEK wrap/unwrap would be KMS API calls, so the KEK never enters
   application memory. Passphrase strength and handling (environment variables
   can leak through `/proc`, shell history and crash dumps) are the operator's
   problem here.
4. **Broadcast key bytes trust the Spark cluster.** Unwrapped DEKs for the
   ALLOWed columns live in executor memory, and possibly in spill or broadcast
   block storage, for the length of a query. Anyone controlling an executor, or
   reading its memory or local disk, can recover them. The Spark cluster is
   inside the trust boundary. Mitigations outside this project: encrypted
   shuffle/spill (`spark.io.encryption.enabled`), RPC authentication and
   encryption (`spark.authenticate`, `spark.network.crypto.enabled`), dedicated
   clusters per sensitivity level, or confidential computing.
5. **Rule-based detection is not adversarial-resistant.** An attacker who knows
   the thresholds can stay under them, for example by spreading pulls over time,
   staying under the row cap, or acting during working hours. Baselines can also
   be "trained" by slowly increasing volume. There is no cross-user correlation.
   Working hours are evaluated in UTC.
6. **No network-layer security is modelled.** There is no TLS between components
   (everything is local), Spark RPC is unauthenticated, and the dashboard has no
   login.

## Smaller known gaps (also out of scope)
- **Ciphertext is not bound to its row.** With write access to the Parquet files,
  two employees' `salary_enc` values (same column, same key) can be swapped
  undetected. AES-GCM with associated data `(employee_id, column, version)` would
  close this.
- **NULL is stored as NULL**, which leaks which cells are empty.
- **Denial reasons include the would-be row count**, which leaks the cardinality
  of the caller's request.
- **Plaintext columns** (`employee_id`, `department`) are readable by anyone with
  disk access, by design (queryability).
- **The demo passphrase fallback.** `demo/run_demo.py` uses a throwaway
  passphrase if none is set; its state is wiped on every run. The CLI and the
  dashboard have no fallback.
- **Results are materialised on the driver**, and there is no streaming export
  path.
- **Single writer.** There is no file lock for concurrent gateways appending to
  the same audit log.
- **No re-encryption job.** Rotation protects *new* writes; old rows stay under
  old key versions until they are rewritten.
- **Spark temp files.** Plaintext from the CSV passes through Spark memory during
  ingest. Spill or temp files are not explicitly protected (see item 4).
