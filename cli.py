"""SecureLakehouse command-line interface.

Examples (run from the project root):

    export SECURELAKEHOUSE_PASSPHRASE='choose-a-passphrase'
    python cli.py ingest --csv data/raw/employees.csv --lake lake
    python cli.py query --lake lake --user sam.analyst --role analyst \
        --department Engineering --columns employee_id,name,salary
    python cli.py audit-verify
    python cli.py detect

``audit-verify`` and ``detect`` need neither the passphrase nor Spark: they read
only the audit log, so they can run with much less privilege than the data.
Every command goes through the same SecureGateway / AuditLog / anomaly.detect()
used by the demo and the dashboard.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from demo.render import banner, format_table
from security import anomaly
from security.audit import AuditLog

DEFAULT_STATE_DIR = "state"
EXIT_DENIED = 3
EXIT_TAMPERED = 4


def _parse_filters(items: list[str]) -> dict[str, str]:
    filters = {}
    for item in items or []:
        if "=" not in item:
            raise SystemExit(f"--filter must look like column=value, got {item!r}")
        k, v = item.split("=", 1)
        filters[k.strip()] = v.strip()
    return filters


def _print_result(result) -> None:
    for col, d in result.decisions.items():
        print(f"  {d.effect.value:<5} {col:<12} {d.reason}")
    print(f"OUTCOME: {result.outcome.upper()} — {result.reason} (audit seq {result.audit_seq})")
    if result.rows:
        print(format_table(result.rows, result.columns))


# --------------------------------------------------------------------------- #
def cmd_ingest(args: argparse.Namespace) -> int:
    from pipeline.context import open_lakehouse, resolve_passphrase
    from pipeline.ingest import ingest_csv

    lh = open_lakehouse(args.lake, args.state_dir, resolve_passphrase())
    n = ingest_csv(lh.spark, args.csv, args.lake, lh.key_manager, mode=args.mode)
    versions = {c: lh.key_manager.active_version(c) for c in lh.key_manager.columns()}
    print(f"Ingested {n} rows into {args.lake} (mode={args.mode}); active key versions: {versions}")
    return 0


def cmd_query(args: argparse.Namespace) -> int:
    from pipeline.context import open_lakehouse, resolve_passphrase
    from security.policy import Subject

    lh = open_lakehouse(args.lake, args.state_dir, resolve_passphrase())
    subject = Subject(args.user, args.role, args.department)
    columns = [c.strip() for c in args.columns.split(",") if c.strip()]
    result = lh.gateway.query(subject, columns, _parse_filters(args.filter))
    _print_result(result)
    return EXIT_DENIED if result.outcome == "denied" else 0


def cmd_rotate_key(args: argparse.Namespace) -> int:
    from pipeline.context import keystore_path, resolve_passphrase
    from security.crypto import KeyManager

    km = KeyManager(keystore_path(args.state_dir), resolve_passphrase())
    new = km.rotate_key(args.column)
    print(f"Rotated {args.column!r}: new writes use v{new}; versions kept: {km.versions(args.column)}")
    return 0


def cmd_audit_verify(args: argparse.Namespace) -> int:
    from pipeline.context import audit_path

    log = AuditLog(audit_path(args.state_dir))
    ok, msg = log.verify()
    print(("INTACT: " if ok else "TAMPERED: ") + msg)
    if ok:
        print(f"head hash: {log.head_hash()}")
    return 0 if ok else EXIT_TAMPERED


def cmd_detect(args: argparse.Namespace) -> int:
    from pipeline.context import audit_path

    log = AuditLog(audit_path(args.state_dir))
    ok, msg = log.verify()
    if not ok:
        # Still run detection, but never silently analyse a log that was edited.
        print(f"WARNING: audit chain is NOT intact ({msg}); alerts may be unreliable.",
              file=sys.stderr)
    events = log.entries()
    alerts = anomaly.detect(events)
    if args.json:
        print(json.dumps([a.as_dict() for a in alerts], indent=2))
    else:
        print(f"Analysed {len(events)} audit events -> {len(alerts)} alerts {anomaly.summarize(alerts)}")
        for a in alerts:
            print(f"  [{a.severity.value:<6}] {a.rule:<20} seq={a.seq:<3} {a.reason}")
    return 0


def cmd_scenario(args: argparse.Namespace) -> int:
    """Replay the demo's scripted scenario through the CLI wiring (fresh state)."""
    from demo.scenario import BREACH_STEPS, LEGIT_STEPS, SimulatedClock, run_steps
    from pipeline.context import open_lakehouse, resolve_passphrase
    from pipeline.ingest import ingest_csv

    shutil.rmtree(args.lake, ignore_errors=True)
    shutil.rmtree(args.state_dir, ignore_errors=True)
    clock = SimulatedClock()
    lh = open_lakehouse(args.lake, args.state_dir, resolve_passphrase(), clock=clock)
    ingest_csv(lh.spark, args.csv, args.lake, lh.key_manager)

    def show(step, result):
        print(f"[{step.at:%H:%M}] {step.subject.user_id:<15} {result.outcome.upper():<7} "
              f"{list(step.columns)} -> {result.reason}")

    print(banner("Legitimate workday"))
    run_steps(lh.gateway, clock, LEGIT_STEPS, show)
    print(banner("Compromised analyst account"))
    run_steps(lh.gateway, clock, BREACH_STEPS, show)
    print(f"\nAudit log written to {Path(args.state_dir) / 'audit.jsonl'}; "
          "run `python cli.py detect` and `python cli.py audit-verify`.")
    return 0


# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cli.py", description="SecureLakehouse CLI")
    p.add_argument("--state-dir", default=DEFAULT_STATE_DIR,
                   help="directory holding keystore.json and audit.jsonl (default: ./state)")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("ingest", help="CSV -> column-encrypted Parquet")
    s.add_argument("--csv", required=True)
    s.add_argument("--lake", required=True)
    s.add_argument("--mode", choices=["overwrite", "append"], default="overwrite")
    s.set_defaults(func=cmd_ingest)

    s = sub.add_parser("query", help="query the lake through the SecureGateway")
    s.add_argument("--lake", required=True)
    s.add_argument("--user", required=True)
    s.add_argument("--role", required=True, choices=["admin", "analyst", "auditor", "support"])
    s.add_argument("--department", required=True)
    s.add_argument("--columns", required=True, help="comma-separated, e.g. employee_id,name,salary")
    s.add_argument("--filter", action="append", metavar="COL=VALUE",
                   help="equality filter on a plaintext column; repeatable")
    s.set_defaults(func=cmd_query)

    s = sub.add_parser("rotate-key", help="create and activate a new key version for a column")
    s.add_argument("--column", required=True)
    s.set_defaults(func=cmd_rotate_key)

    s = sub.add_parser("audit-verify", help="verify the audit log hash chain")
    s.set_defaults(func=cmd_audit_verify)

    s = sub.add_parser("detect", help="run insider-threat rules over the audit log")
    s.add_argument("--json", action="store_true", help="emit alerts as JSON")
    s.set_defaults(func=cmd_detect)

    s = sub.add_parser("scenario", help="replay the demo scenario (wipes --lake and --state-dir)")
    s.add_argument("--csv", default="data/raw/employees.csv")
    s.add_argument("--lake", default="lake")
    s.set_defaults(func=cmd_scenario)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
