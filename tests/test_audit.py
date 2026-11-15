"""Hash-chained audit log."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from security.audit import GENESIS_HASH, AuditLog


def _record(log: AuditLog, user: str = "u", outcome: str = "served", rows: int = 1) -> dict:
    return log.record(
        user=user, role="analyst", department="Engineering", columns=["employee_id"],
        decisions={"employee_id": {"effect": "ALLOW", "reason": "ok"}},
        outcome=outcome, row_count=rows, requested_row_count=rows, reason="test",
    )


def _lines(log: AuditLog) -> list[str]:
    return log.path.read_text().splitlines()


@pytest.fixture()
def log5(tmp_path) -> AuditLog:
    log = AuditLog(tmp_path / "audit.jsonl")
    for i in range(5):
        _record(log, user=f"user{i}")
    return log


def test_empty_log_is_valid(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    ok, msg = log.verify()
    assert ok and "empty" in msg
    assert log.head_hash() == GENESIS_HASH


def test_fresh_log_verifies_intact(log5):
    ok, msg = log5.verify()
    assert ok, msg
    assert "5 entries" in msg


def test_entries_are_chained(log5):
    entries = log5.entries()
    assert entries[0]["prev_hash"] == GENESIS_HASH
    for prev, cur in zip(entries, entries[1:]):
        assert cur["prev_hash"] == prev["hash"]
        assert cur["seq"] == prev["seq"] + 1
    assert log5.head_hash() == entries[-1]["hash"]


def test_edit_of_past_entry_detected_with_correct_seq(log5):
    lines = _lines(log5)
    entry = json.loads(lines[2])
    entry["user"] = "someone-else"
    lines[2] = json.dumps(entry)
    log5.path.write_text("\n".join(lines) + "\n")
    ok, msg = log5.verify()
    assert not ok
    assert "seq=2" in msg and "modified" in msg


def test_edit_with_recomputed_hash_detected_at_next_entry(log5):
    from demo.scenario import simulate_tampering

    simulate_tampering(log5.path, 1, {"outcome": "denied"}, recompute_own_hash=True)
    ok, msg = log5.verify()
    assert not ok
    assert "seq=2" in msg and "prev_hash" in msg


def test_deleting_middle_entry_detected(log5):
    lines = _lines(log5)
    del lines[2]
    log5.path.write_text("\n".join(lines) + "\n")
    ok, msg = log5.verify()
    assert not ok
    assert "position 2" in msg and "seq=3" in msg


def test_reordering_entries_detected(log5):
    lines = _lines(log5)
    lines[1], lines[3] = lines[3], lines[1]
    log5.path.write_text("\n".join(lines) + "\n")
    ok, _ = log5.verify()
    assert not ok


def test_corrupted_json_detected(log5):
    with log5.path.open("a") as fh:
        fh.write("{not json\n")
    ok, msg = log5.verify()
    assert not ok and "corrupted" in msg


def test_appending_continues_chain_across_instances(log5):
    reopened = AuditLog(log5.path)
    e = _record(reopened, user="late")
    assert e["seq"] == 5
    assert reopened.verify()[0]


def test_invalid_outcome_rejected(tmp_path):
    with pytest.raises(ValueError):
        _record(AuditLog(tmp_path / "a.jsonl"), outcome="maybe")


def test_injected_clock_is_used(tmp_path):
    t = datetime(2026, 1, 3, 2, 30, tzinfo=timezone.utc)
    log = AuditLog(tmp_path / "a.jsonl", clock=lambda: t)
    assert _record(log)["ts"] == t.isoformat()


def test_tail_truncation_is_not_detected_without_anchor(log5):
    """Documented limitation: dropping the NEWEST entries leaves a valid chain.
    Comparing against an externally anchored head hash is what catches it."""
    anchored_head = log5.head_hash()
    lines = _lines(log5)
    log5.path.write_text("\n".join(lines[:-1]) + "\n")
    assert log5.verify()[0] is True
    assert log5.head_hash() != anchored_head
