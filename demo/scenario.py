"""The scripted scenario shared by the demo, the CLI (``cli.py scenario``) and the
dashboard's "run breach simulation" button.

Timeline (simulated, UTC — Tuesday 2026-11-10):

* 09:00-15:30  legitimate work by admin / analyst / support / auditor.
               sam.analyst (Engineering) builds a normal baseline of small queries.
* 23:40-23:52  sam.analyst's account is compromised. The attacker probes for SSNs,
               tries to read the physical ciphertext column, tries a bulk export
               of names, and tries to read another department's salaries.

Steps are plain data so they can be printed, replayed and tested.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from pipeline.gateway import QueryResult, SecureGateway
from security.policy import Subject

DAY = datetime(2026, 11, 10, tzinfo=timezone.utc)  # a Tuesday

ADMIN = Subject("alice.admin", "admin", "IT")
ANALYST = Subject("sam.analyst", "analyst", "Engineering")
SUPPORT = Subject("taylor.support", "support", "HR")
AUDITOR = Subject("ari.auditor", "auditor", "Compliance")
# Separate users for the role comparison, so it does not pollute the per-user
# baselines of the main characters (the detector learns per user).
CMP_SUPPORT = Subject("casey.support", "support", "HR")
CMP_ANALYST = Subject("jordan.analyst", "analyst", "Finance")


@dataclass(frozen=True)
class Step:
    at: datetime
    subject: Subject
    columns: tuple[str, ...]
    narration: str
    filters: dict[str, str] = field(default_factory=dict)


def _t(hour: int, minute: int = 0) -> datetime:
    return DAY + timedelta(hours=hour, minutes=minute)


ROLE_COMPARISON_COLUMNS = ("employee_id", "name", "ssn", "salary")

LEGIT_STEPS: tuple[Step, ...] = (
    # Same column set, four roles -> four different answers.
    Step(_t(9, 0), ADMIN, ROLE_COMPARISON_COLUMNS, "admin reads everything (no ABAC limits)"),
    Step(_t(9, 5), AUDITOR, ROLE_COMPARISON_COLUMNS, "auditor: sensitive values masked"),
    Step(_t(9, 10), CMP_SUPPORT, ROLE_COMPARISON_COLUMNS,
         "support: salary is DENY and name exceeds the row cap -> whole query refused"),
    Step(_t(9, 15), CMP_ANALYST, ROLE_COMPARISON_COLUMNS,
         "analyst: ssn is DENY -> whole query refused (fail closed)"),
    # Normal day-to-day work.
    Step(_t(9, 30), SUPPORT, ("employee_id", "name", "email", "ssn"),
         "support looks up one employee (ssn masked)", {"employee_id": "E007"}),
    Step(_t(10, 0), ANALYST, ("employee_id", "name", "salary"),
         "analyst: own-department salary report (row filter applied)"),
    Step(_t(11, 30), ANALYST, ("employee_id", "salary"), "analyst: salary follow-up"),
    Step(_t(14, 0), ANALYST, ("employee_id", "name"),
         "analyst: team roster, filtered to own department", {"department": "Engineering"}),
    Step(_t(15, 30), ANALYST, ("employee_id", "name", "salary"), "analyst: end-of-day refresh"),
)

BREACH_STEPS: tuple[Step, ...] = (
    Step(_t(23, 40), ANALYST, ("employee_id", "ssn"), "attacker probes for SSNs"),
    Step(_t(23, 42), ANALYST, ("employee_id", "name", "ssn"),
         "attacker retries SSNs, scoped to Finance", {"department": "Finance"}),
    Step(_t(23, 44), ANALYST, ("employee_id", "ssn_enc", "ssn_kv"),
         "attacker requests the raw ciphertext column (no rule -> default-deny)"),
    Step(_t(23, 46), ANALYST, ("employee_id", "name", "department"),
         "attacker attempts a bulk export of every employee's name (row cap)"),
    Step(_t(23, 48), ANALYST, ("employee_id", "salary"),
         "attacker asks for Finance salaries (department scoping)", {"department": "Finance"}),
    Step(_t(23, 52), ANALYST, ("employee_id", "email"),
         "attacker settles for emails -> only redacted values come back"),
)


class SimulatedClock:
    """A settable clock injected into AuditLog so the scenario is reproducible."""

    def __init__(self, start: datetime = DAY) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now


def run_steps(
    gateway: SecureGateway,
    clock: SimulatedClock,
    steps: tuple[Step, ...],
    on_result: Optional[Callable[[Step, QueryResult], None]] = None,
) -> list[QueryResult]:
    results = []
    for step in steps:
        clock.now = step.at
        result = gateway.query(step.subject, list(step.columns), step.filters or None)
        results.append(result)
        if on_result:
            on_result(step, result)
    return results


def simulate_tampering(audit_file, seq: int, changes: dict, recompute_own_hash: bool = False) -> dict:
    """Play the attacker: edit audit entry ``seq`` in place on disk.

    With ``recompute_own_hash=True`` the attacker also fixes up the edited entry's
    own hash — the chain still breaks, one entry later, because the NEXT entry's
    ``prev_hash`` no longer matches. Returns the edited entry.
    """
    import json
    from pathlib import Path

    from security.audit import canonical_json, compute_hash

    path = Path(audit_file)
    lines = path.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines):
        entry = json.loads(line)
        if entry["seq"] == seq:
            entry.update(changes)
            if recompute_own_hash:
                entry["hash"] = compute_hash({k: v for k, v in entry.items() if k != "hash"})
            lines[i] = canonical_json(entry)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return entry
    raise KeyError(f"no audit entry with seq={seq}")
