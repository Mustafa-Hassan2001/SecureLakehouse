"""CLI wiring for the commands that need no Spark (audit-verify, detect)."""

from __future__ import annotations

import json

import cli
from demo.scenario import simulate_tampering
from security.audit import AuditLog


def _write_log(state_dir, n=4, outcome="denied"):
    log = AuditLog(state_dir / "audit.jsonl")
    for _ in range(n):
        log.record(
            user="mallory", role="analyst", department="Eng", columns=["ssn"],
            decisions={"ssn": {"effect": "DENY", "reason": "x"}}, outcome=outcome,
            row_count=0, requested_row_count=12, reason="test",
        )
    return log


def test_parser_description():
    assert cli.build_parser().description == "SecureLakehouse CLI"


def test_audit_verify_intact_and_tampered(tmp_path, capsys):
    log = _write_log(tmp_path)
    assert cli.main(["--state-dir", str(tmp_path), "audit-verify"]) == 0
    assert "INTACT" in capsys.readouterr().out
    simulate_tampering(log.path, 1, {"user": "innocent"})
    assert cli.main(["--state-dir", str(tmp_path), "audit-verify"]) == cli.EXIT_TAMPERED
    assert "seq=1" in capsys.readouterr().out


def test_detect_json(tmp_path, capsys):
    _write_log(tmp_path)
    assert cli.main(["--state-dir", str(tmp_path), "detect", "--json"]) == 0
    alerts = json.loads(capsys.readouterr().out)
    assert any(a["rule"] == "DENY_BURST" and a["user"] == "mallory" for a in alerts)


def test_detect_warns_on_tampered_log(tmp_path, capsys):
    log = _write_log(tmp_path)
    simulate_tampering(log.path, 0, {"outcome": "served"})
    cli.main(["--state-dir", str(tmp_path), "detect"])
    assert "NOT intact" in capsys.readouterr().err
