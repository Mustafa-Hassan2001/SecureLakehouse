# CV and portfolio material

## CV entry

**SecureLakehouse — Encryption, Access Control & Insider-Threat Detection for Big Data Pipelines**
*Personal project · Python, PySpark, Parquet, cryptography, pytest, Streamlit*

- Designed and built a PySpark/Parquet data lake with **column-level envelope
  encryption**: a PBKDF2-derived master key wraps per-column, versioned data keys,
  so key rotation never breaks reads of older data and the keystore on disk never
  holds plaintext key material.
- **Diagnosed and fixed a silent data-corruption bug specific to distributed
  execution.** A stateful key manager captured in Spark UDFs was copied into each
  executor task, where every copy minted its own key; 35–36 of 40 rows became
  undecryptable with no error raised. Fixed it by resolving key material on the
  driver and broadcasting immutable bytes, and wrote a regression test that
  reproduces the original failure.
- Implemented a **hybrid RBAC/ABAC access gateway** as the only read path. It
  provides per-column ALLOW/MASK/DENY decisions, department-scoped row-level
  security, per-query row caps against bulk exfiltration, default-deny, and
  fail-closed refusal of any query containing a denied column.
- Built a **tamper-evident SHA-256 hash-chained audit log** (Certificate
  Transparency-style) that pinpoints the first edited, deleted or reordered entry.
  Also built a **rule-based insider-threat detector** (volume spike, new
  sensitive column, deny burst, off-hours) that works from audit metadata only and
  gives plain-English explanations.
- Verified the central security claim directly: tests scan the raw Parquet bytes
  *and* the decoded values for plaintext SSNs, with a positive control. The suite
  has 107 tests and passes offline on Python 3.10 and 3.13. Wrote a threat model
  that explicitly lists what is out of scope.

*Shorter variant (2 bullets):*
- Built a PySpark data lake with column-level envelope encryption, an RBAC/ABAC
  gateway (row-level security, exfiltration caps, fail-closed) and a hash-chained
  audit log feeding an explainable insider-threat detector; 107 offline tests.
- Found and fixed a distributed-systems bug where per-executor copies of a key
  manager silently corrupted ~90% of encrypted rows (35–36 of 40). Fixed with driver-side key
  resolution plus Spark broadcast; regression-tested.

## Statement of Purpose paragraph

> In building SecureLakehouse, a PySpark data lake with column-level encryption
> and an attribute-based access gateway, the most instructive moment came from
> code that was correct in every unit test. My key manager created a column's
> encryption key lazily, on first use. Once Spark ran that logic inside UDFs,
> each executor task received its own serialized copy of the manager. Every copy
> minted its own "version 1" key and raced to save it, and only one survived.
> The job finished without an error, but when I measured it, 35 of 40 rows could
> never be decrypted again. Fixing it meant thinking about the system rather than
> the function: mutable security state cannot cross the driver/executor boundary.
> So I resolved all key material once on the driver and broadcast immutable bytes
> to pure encryption functions. Soon after, the same lesson appeared in another
> form: executors could not import modules the driver could. The experience
> showed me that in big-data systems, security guarantees depend on the execution
> model as much as on the cryptography. That gap between distributed systems and
> security engineering is what I want to study at Master's level.

(Adjust the closing sentence to the specific programme or research group.)

## Suggested portfolio page structure

1. **One-line hook.** "A data lake where an analyst's compromised account gets
   blocked, and caught, at four different layers."
2. **30-second demo.** A GIF or short video of `python demo/run_demo.py` or the
   dashboard: role comparison, then the breach replay, then the alerts, then
   tampering detected.
3. **The problem.** Data lakes concentrate sensitive data and make bulk reads
   cheap. Why storage-layer and gateway-layer controls matter more than UI checks.
4. **Architecture diagram.** Reuse the README diagram, with one sentence per
   component.
5. **Deep dive: the Spark bug.** The naive code (5 lines), the failure (35/40 rows
   undecryptable), why it happens (per-task closure pickling, separate Python
   workers), the fix (driver-side resolution plus broadcast), and the regression
   test. This is the centrepiece.
6. **Security design choices.** Envelope encryption and rotation; fail closed vs.
   partial results; why masks are constants; ABAC only where plaintext is
   revealed; rules instead of ML.
7. **Evidence.** The test-case table, the plaintext-on-disk scan with its
   positive control, and the offline test run.
8. **Threat model and limitations.** Show the out-of-scope list. Being honest
   about limits is a strength.
9. **What I'd build next.** KMS-backed KEK; AES-GCM with row-bound associated
   data; externally anchored or WORM audit log; IdP integration; re-encryption job
   after rotation; streaming exports with per-batch audit.
10. **Links.** Repository, README, threat model.

## Likely interview questions (and where the answer lives)

| Question | Where |
|---|---|
| Why envelope encryption instead of one key? | README design decision 2; `security/crypto.py` docstring |
| Why does the key-manager-in-a-UDF bug happen even in `local[*]`? | README design decision 1; `tests/test_spark_key_isolation.py` |
| What exactly is in the broadcast, and who can read it? | `pipeline/gateway.py` step 7; threat model, out of scope #4 |
| Why refuse the whole query instead of returning the allowed columns? | README design decision 3 |
| Can an attacker defeat the hash chain? | Yes, by rewriting the whole file or truncating the tail; threat model, out of scope #2 |
| Why not ML for anomaly detection? | `security/anomaly.py` docstring; README design decision 5 |
| How do you know the Parquet files hold no plaintext? | `test_no_plaintext_ssn_in_parquet_files_on_disk` plus its positive control |
| What breaks first at scale? | Driver-side result collection; single-writer audit log; per-row Fernet object construction in UDFs (Pandas UDFs would batch it) |
