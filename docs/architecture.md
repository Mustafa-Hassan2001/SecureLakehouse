# Architecture

This document walks through the data flow module by module. The guiding rule:
**security decisions live in `security/` and `pipeline/gateway.py`; every entry
point (demo, CLI, dashboard) only calls them.** `pipeline/context.py:open_lakehouse`
is the single place the components are assembled, so no entry point can wire up a
weaker configuration.

```
security/  (pure Python, no Spark)      pipeline/  (Spark)              entry points
  crypto.py   ◄──────────────────────── ingest.py, gateway.py   ◄────── demo/run_demo.py
  policy.py   ◄──────────────────────── gateway.py              ◄────── cli.py
  audit.py    ◄──────────────────────── gateway.py              ◄────── app.py
  anomaly.py  ◄─────────────────────────────────────────────────────── (reads audit only)
```

---

## 1. `security/crypto.py`: envelope encryption and key management

### Key hierarchy
```
passphrase ──PBKDF2-HMAC-SHA256(salt 16B, 600k iters)──► KEK  (never persisted)
KEK ──Fernet.encrypt──► wrapped DEK(column, version)        (persisted in keystore.json)
DEK ──Fernet.encrypt──► cell ciphertext                     (persisted in Parquet)
```

### Keystore file (`state/keystore.json`)
```json
{
  "format_version": 1,
  "kdf": {"algorithm": "PBKDF2-HMAC-SHA256", "salt": "<b64>", "iterations": 600000},
  "kek_check": "<Fernet token of a public constant>",
  "columns": {
    "ssn": {"active_version": 2,
            "versions": {"1": {"wrapped_dek": "gAAAA…", "created_at": "…"},
                         "2": {"wrapped_dek": "gAAAA…", "created_at": "…"}}}
  }
}
```
- **Opening** re-derives the KEK from the passphrase plus the stored salt and
  iterations, then decrypts `kek_check`. A failure raises `PermissionError` right
  away. A second, independent check: every DEK unwrap also raises
  `PermissionError` on `InvalidToken`. This holds even if an attacker forges
  `kek_check` (tested).
- **Minting** (`_mint`): `Fernet.generate_key()` creates 32 random bytes (16 for
  HMAC, 16 for AES), which are wrapped under the KEK. The version is
  `max(existing) + 1`. The keystore is persisted atomically (temp file, `fsync`,
  `chmod 600`, `os.replace`).
- **Rotation** (`rotate_key`) mints a new version and makes it active. Old
  versions are never removed, because existing ciphertext references them by
  `<col>_kv`.
- Unwrapped DEKs are cached **in memory only**.

### Two API layers
| Layer | Functions | Where it may run |
|---|---|---|
| Stateful | `KeyManager.encrypt_value / decrypt_value / rotate_key / export_key_material` | driver only |
| Pure | `encrypt_with_key(key, value)`, `decrypt_with_key(key, token)` | anywhere, including Spark executors |

`KeyManager.__reduce__` raises `TypeError`, so pickling one (which is what
capturing it in a UDF closure does) fails loudly. `KeyMaterial` has
`repr=False` on its key bytes so they never end up in logs or tracebacks.

---

## 2. `security/policy.py`: hybrid RBAC + ABAC

`decide(subject, column, requested_row_count) -> Decision(effect, reason, row_filter)`
evaluates in this order:

1. Unknown role → **DENY** (default-deny).
2. No `ColumnRule` for the column → **DENY** (default-deny).
3. Role in `rule.mask` → **MASK**.
4. Role not in `rule.allow` → **DENY**.
5. Role is ALLOWed. For non-privileged roles, the ABAC conditions apply:
   - `max_rows_per_query` exceeded → **DENY** (bulk-exfiltration control);
   - `department_scoped` → **ALLOW** with `RowFilter("department", subject.department)`.
6. Otherwise → **ALLOW**.

`row_filter_for(subject, column)` is exposed separately because the gateway must
know the row filters *before* it can count rows, and the count is an input to
`decide`.

Default policy (`default_policy()`):

| column      | admin | analyst                   | support       | auditor |
|-------------|-------|---------------------------|---------------|---------|
| employee_id | ALLOW | ALLOW                     | ALLOW         | ALLOW   |
| department  | ALLOW | ALLOW                     | ALLOW         | ALLOW   |
| name        | ALLOW | ALLOW (cap 5)             | ALLOW (cap 5) | MASK    |
| email       | ALLOW | MASK                      | ALLOW (cap 5) | MASK    |
| ssn         | ALLOW | DENY                      | MASK          | MASK    |
| salary      | ALLOW | ALLOW (own dept, cap 5)   | DENY          | MASK    |

`admin` is in `privileged_roles` and so bypasses caps and scoping. It is still
audited and still evaluated by every detection rule.

---

## 3. `pipeline/ingest.py`: CSV → encrypted Parquet

```
spark.read.csv(header, inferSchema)               # logical schema recorded
        │
        ▼  driver
km.export_key_material(sensitive, create_missing=True)
        │   → {col: KeyMaterial(active_version, {v: key_bytes})}
        ▼
payload = {col: {"version": v, "key": active_key_bytes}}   # active key only
bc = sparkContext.broadcast(payload)
        │
        ▼  executors (per row)
<col>_enc = encrypt_with_key(bc.value[col]["key"], str(value))
<col>_kv  = lit(version)
drop <col>
        │
        ▼
df.write.mode(overwrite|append).parquet(lake)  →  bc.destroy()
lake/_securelakehouse_meta.json  (sensitive column list + logical types)
```

- Only the **active** key per column is broadcast, because encryption never
  needs older versions.
- The broadcast is destroyed in a `finally` *after* the write action. DataFrames
  are lazy, so destroying it earlier would break the job.
- The sidecar file starts with `_`, which Spark ignores when reading the
  directory. The gateway uses it to cast decrypted strings back to `int`, etc.
- `append` mode checks that the schema matches the existing lake. This is how
  data written after a key rotation lands next to older data.

---

## 4. `pipeline/gateway.py`: SecureGateway, the only read path

`query(subject, columns, filters=None) -> QueryResult`

1. **De-duplicate** the columns, keeping order. An empty request → denied.
2. **Validate filters.** Each filter column must be plaintext, must exist, and
   must be ALLOWed for the caller. Otherwise → denied (no inference oracle).
3. **Row filters.** Collect `policy.row_filter_for(subject, c)` across the
   requested columns. They apply to the whole result, because rows are the unit
   of row-level security.
4. **Count.** Apply the user filters and row filters, then `count()`. This is the
   `requested_row_count`.
5. **Decide.** Call `policy.decide(subject, c, count)` for each column. A column
   that has a rule but is absent from the lake becomes DENY.
6. **Fail closed.** Any DENY → write one `denied` audit event and return no rows.
7. **Keys, least privilege.** `export_key_material` is called for *ALLOWed
   sensitive* columns only, with all their versions, and broadcast.
8. **Project:**
   - ALLOW + sensitive → `decrypt_udf(<col>_enc, <col>_kv).cast(logical_type)`,
     where the UDF picks the key by each row's version;
   - ALLOW + plaintext → the column itself;
   - MASK → `lit("***REDACTED***")`, with no key and no decryption.
9. **Collect**, ordered by `employee_id`. Destroy the broadcast in `finally`.
10. **Audit.** Write exactly one event: `served` (all ALLOW) or `masked` (any
    MASK). If any step raises, the wrapper writes an `error` event and re-raises,
    so nothing is returned and the attempt is still recorded.

---

## 5. `security/audit.py`: hash-chained audit log

One JSON object per line:

```json
{"seq": 9, "ts": "2026-11-10T23:40:00+00:00", "user": "sam.analyst", "role": "analyst",
 "department": "Engineering", "columns": ["employee_id","ssn"], "filters": {},
 "decisions": {"employee_id": {"effect":"ALLOW","reason":"…"}, "ssn": {"effect":"DENY","reason":"…"}},
 "outcome": "denied", "row_count": 0, "requested_row_count": 12,
 "reason": "denied: ssn: role 'analyst' has no access to 'ssn'",
 "prev_hash": "<hash of seq 8>", "hash": "<sha256 of this entry without 'hash'>"}
```

- `hash = SHA256(canonical_json(entry minus "hash"))`. Canonical JSON means sorted
  keys and no whitespace. The genesis `prev_hash` is 64 zeros.
- `record()` appends a line, then calls `flush` and `fsync`.
- `verify()` checks every entry in order: `seq == position` (catches deletion,
  insertion, reordering), `prev_hash ==` the previous entry's hash (catches
  deletion, reordering, or a rewritten predecessor), and the recomputed hash
  equals the stored hash (catches in-place edits). It returns the first failure.
- The clock is injectable, so the demo can replay a simulated day reproducibly.
- **No data values are ever logged**, only metadata. This is tested.

---

## 6. `security/anomaly.py`: insider-threat rules

`detect(events, sensitive_columns, config) -> list[Alert]` makes one pass in log
order and keeps per-user state. Every rule uses only events *before* the current
one as history.

| Rule | Trigger | Severity |
|---|---|---|
| `VOLUME_SPIKE` | `requested_row_count > max(mean + 3σ, 2·mean)` over the user's last ≤20 queries (needs ≥3) | HIGH if sensitive columns were involved, else MEDIUM |
| `NEW_SENSITIVE_COLUMN` | a sensitive column absent from all of the user's prior events, provided the user has *some* prior sensitive history; the history is updated after the check, so same-event columns are not "prior" to each other | HIGH for `ssn`, else MEDIUM |
| `DENY_BURST` | ≥3 `denied` outcomes within the user's last 5 queries; one alert per burst | HIGH |
| `OFF_HOURS` | sensitive column requested outside 08:00–19:00 UTC or at the weekend | MEDIUM if plaintext rows were returned, else LOW |

Each `Alert` carries `rule`, `severity`, `user`, `seq` (the event to inspect),
`ts` and a specific plain-English `reason`.

---

## 7. Entry points

- `demo/scenario.py` holds the scripted workday and breach as plain data
  (`Step`s), a `SimulatedClock`, and `simulate_tampering()`. The demo, `cli.py
  scenario` and the dashboard's breach button all replay the *same* steps.
- `demo/run_demo.py` tells the story and also shows what an attacker with disk
  access sees (pyarrow read of raw Parquet) and what the keystore holds.
- `cli.py` provides `ingest`, `query`, `rotate-key`, `audit-verify`, `detect` and
  `scenario`. `audit-verify` and `detect` don't need the passphrase or Spark.
- `app.py` is the Streamlit presentation layer, with no security logic (see the
  header comment).

## 8. `pipeline/spark_session.py`

`local[*]`, appName `securelakehouse`, bound to `127.0.0.1`, UI disabled, session
time zone UTC, warehouse dir in the system temp dir (so no `./spark-warehouse`).
It sets `PYSPARK_PYTHON` to the current interpreter, and puts the project root on
`PYTHONPATH` *before* the JVM starts, so executor Python workers can import
`security.*` (see the README, design decision 1).
