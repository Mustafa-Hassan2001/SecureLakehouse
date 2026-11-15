"""End-to-end narrated demo of SecureLakehouse.

Run from the project root:

    SECURELAKEHOUSE_PASSPHRASE='choose-a-passphrase' python demo/run_demo.py

Everything is written under ./demo_output/ (recreated on every run), so the
output is reproducible: same queries, same simulated clock, same decisions,
same alerts — and even the same audit head hash, because the log holds only
metadata and simulated timestamps. Only ciphertexts and wrapped keys differ per
run (random keys, salts and IVs).
"""

from __future__ import annotations

import json
import os
import pickle
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pyarrow.parquet as pq  # noqa: E402

from demo.render import banner, format_table  # noqa: E402
from demo.scenario import (  # noqa: E402
    BREACH_STEPS, LEGIT_STEPS, SimulatedClock, Step, run_steps, simulate_tampering,
)
from pipeline.context import PASSPHRASE_ENV, audit_path, keystore_path, open_lakehouse  # noqa: E402
from pipeline.gateway import QueryResult  # noqa: E402
from pipeline.ingest import ingest_csv  # noqa: E402
from security import anomaly  # noqa: E402

OUT = ROOT / "demo_output"
LAKE = OUT / "lake"
STATE = OUT / "state"
CSV = ROOT / "data" / "raw" / "employees.csv"


def show_result(step: Step, result: QueryResult) -> None:
    s = step.subject
    filt = f"  filters={step.filters}" if step.filters else ""
    print(f"\n[{step.at:%H:%M}] {s.user_id} ({s.role}, {s.department}) -> {list(step.columns)}{filt}")
    print(f"        {step.narration}")
    for col, d in result.decisions.items():
        print(f"        {d.effect.value:<5} {col:<12} {d.reason}")
    print(f"        OUTCOME: {result.outcome.upper()} — {result.reason}  (audit seq {result.audit_seq})")
    if result.rows:
        print("\n" + "\n".join("        " + ln for ln in format_table(result.rows, result.columns).splitlines()))


def main() -> int:
    passphrase = os.environ.get(PASSPHRASE_ENV)
    if not passphrase:
        # Demo convenience only: the keystore lives in ./demo_output and is wiped on
        # every run, so this value protects nothing real. The CLI has no fallback.
        passphrase = "demo-only-passphrase-not-a-secret"
        print(f"(note: {PASSPHRASE_ENV} not set — using a throwaway demo passphrase)")

    shutil.rmtree(OUT, ignore_errors=True)
    clock = SimulatedClock()
    lh = open_lakehouse(LAKE, STATE, passphrase, clock=clock)

    # ------------------------------------------------------------------ #
    print(banner("1. INGEST — CSV -> column-encrypted Parquet"))
    n = ingest_csv(lh.spark, CSV, LAKE, lh.key_manager)
    print(f"Ingested {n} rows from {CSV.relative_to(ROOT)} into {LAKE.relative_to(ROOT)}/")
    part = sorted(LAKE.glob("*.parquet"))[0]
    table = pq.read_table(part)
    print(f"\nWhat an attacker with raw disk access sees (pyarrow, NOT the gateway): {part.name}")
    print(f"  physical columns: {table.column_names}")
    first = table.slice(0, 1).to_pylist()[0]
    for k, v in first.items():
        print(f"  {k:<12} = {str(v)[:70]}{'...' if len(str(v)) > 70 else ''}")
    ks = json.loads(keystore_path(STATE).read_text())
    print(f"\nKeystore ({keystore_path(STATE).relative_to(ROOT)}): KDF={ks['kdf']['algorithm']}, "
          f"iterations={ks['kdf']['iterations']:,}")
    for col, entry in ks["columns"].items():
        wrapped = entry["versions"][str(entry["active_version"])]["wrapped_dek"]
        print(f"  {col:<7} v{entry['active_version']}  wrapped DEK = {wrapped[:44]}...")
    print("  (only wrapped DEKs on disk; the KEK is re-derived from the passphrase)")

    print("\nSpark guardrail: trying to pickle the KeyManager (what a UDF closure would do)...")
    try:
        pickle.dumps(lh.key_manager)
    except TypeError as exc:
        print(f"  refused -> TypeError: {exc}")

    # ------------------------------------------------------------------ #
    print(banner("2. LEGITIMATE WORKDAY — same lake, different answers per role"))
    run_steps(lh.gateway, clock, LEGIT_STEPS, show_result)

    # ------------------------------------------------------------------ #
    print(banner("3. BREACH — sam.analyst's account is compromised at 23:40"))
    run_steps(lh.gateway, clock, BREACH_STEPS, show_result)

    # ------------------------------------------------------------------ #
    print(banner("4. INSIDER-THREAT DETECTION — rules over the audit trail only"))
    events = lh.audit.entries()
    alerts = anomaly.detect(events)
    print(f"Analysed {len(events)} audit events -> {len(alerts)} alerts "
          f"{anomaly.summarize(alerts)}\n")
    for a in alerts:
        print(f"  [{a.severity.value:<6}] {a.rule:<20} seq={a.seq:<3} {a.reason}")

    # ------------------------------------------------------------------ #
    print(banner("5. AUDIT INTEGRITY — hash chain vs. an attacker editing history"))
    ok, msg = lh.audit.verify()
    print(f"verify() before tampering: intact={ok} — {msg}")
    head = lh.audit.head_hash()
    print(f"Head hash to anchor externally: {head}")

    probe = next(e for e in events if e["user"] == "sam.analyst" and "ssn" in e["columns"])
    print(f"\nAttacker rewrites seq={probe['seq']} (the first SSN probe) to blame someone else "
          f"and hide the denial...")
    simulate_tampering(audit_path(STATE), probe["seq"],
                       {"user": "alice.admin", "role": "admin", "outcome": "served"})
    ok, msg = lh.audit.verify()
    print(f"verify() after naive edit:        intact={ok} — {msg}")

    print("\nSmarter attacker also recomputes the edited entry's own hash...")
    simulate_tampering(audit_path(STATE), probe["seq"], {}, recompute_own_hash=True)
    ok, msg = lh.audit.verify()
    print(f"verify() after hash recompute:    intact={ok} — {msg}")
    print("(Rewriting EVERY later hash would pass verify(); that is why the head hash "
          "must be anchored outside the attacker's reach — see docs/threat-model.md.)")

    print(banner("DONE"))
    print(f"Artifacts in {OUT.relative_to(ROOT)}/ (lake, keystore, audit log).")
    lh.spark.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
