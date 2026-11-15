"""Tamper-evident, append-only audit log (a SHA-256 hash chain).

Each line of the JSON-lines file is one event. Every event stores ``prev_hash``
(the hash of the previous event) and ``hash`` = SHA-256 over the canonical JSON of
the event *including* ``prev_hash``. Changing, deleting, inserting or reordering
any past event therefore breaks either that event's own hash or the next event's
link — the same idea as Certificate Transparency logs and git commits.

What this does NOT give you (see docs/threat-model.md):
* An attacker who can rewrite the *entire* file can recompute every hash. Hash
  chains detect tampering relative to a trusted reference point, so the latest
  ``head_hash()`` should be anchored somewhere the attacker cannot write
  (a write-once store, a separate system, a printed report).
* Truncating the newest events is undetectable without such an anchor.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Optional, Sequence

GENESIS_HASH = "0" * 64

Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def canonical_json(obj: Mapping[str, Any]) -> str:
    """Deterministic serialization: sorted keys, no whitespace. Hashing a
    non-canonical form would make verification depend on dict ordering."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_hash(entry_without_hash: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(entry_without_hash).encode("utf-8")).hexdigest()


class AuditLog:
    """Append-only, hash-chained JSON-lines audit log."""

    def __init__(self, path: str | os.PathLike[str], clock: Optional[Clock] = None) -> None:
        """``clock`` is injectable so the demo and tests can simulate time
        (e.g. an off-hours access). Production uses the system UTC clock."""
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._clock: Clock = clock or _utc_now

    # ------------------------------------------------------------------ #
    def entries(self) -> list[dict[str, Any]]:
        """All events, oldest first (no verification — call :meth:`verify`)."""
        return list(self._iter_entries())

    def _iter_entries(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    yield json.loads(line)

    def head_hash(self) -> str:
        """Hash of the newest event (GENESIS_HASH for an empty log). Anchor this
        value externally to also detect truncation or a full-chain rewrite."""
        last = GENESIS_HASH
        for entry in self._iter_entries():
            last = entry["hash"]
        return last

    def _tail(self) -> tuple[int, str]:
        """(next sequence number, previous hash)."""
        seq, prev = 0, GENESIS_HASH
        for entry in self._iter_entries():
            seq, prev = entry["seq"] + 1, entry["hash"]
        return seq, prev

    # ------------------------------------------------------------------ #
    def record(
        self,
        *,
        user: str,
        role: str,
        department: str,
        columns: Sequence[str],
        decisions: Mapping[str, Mapping[str, str]],
        outcome: str,
        row_count: int,
        requested_row_count: int,
        reason: str,
        filters: Optional[Mapping[str, str]] = None,
    ) -> dict[str, Any]:
        """Append exactly one event describing one query and return it.

        ``outcome`` is ``served`` (all columns ALLOW), ``masked`` (some MASK, none
        DENY), ``denied`` (whole query refused) or ``error`` (gateway failure;
        fail-closed, nothing returned). ``row_count`` is rows actually returned;
        ``requested_row_count`` is rows the query *would* have touched — the
        detector uses it so a denied bulk-export attempt is still visible.
        Values from the data are never written here, only metadata.
        """
        if outcome not in {"served", "masked", "denied", "error"}:
            raise ValueError(f"invalid outcome {outcome!r}")
        seq, prev_hash = self._tail()
        entry: dict[str, Any] = {
            "seq": seq,
            "ts": self._clock().astimezone(timezone.utc).isoformat(),
            "user": user,
            "role": role,
            "department": department,
            "columns": list(columns),
            "filters": dict(filters or {}),
            "decisions": {c: dict(d) for c, d in decisions.items()},
            "outcome": outcome,
            "row_count": int(row_count),
            "requested_row_count": int(requested_row_count),
            "reason": reason,
            "prev_hash": prev_hash,
        }
        entry["hash"] = compute_hash(entry)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(canonical_json(entry) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return entry

    # ------------------------------------------------------------------ #
    def verify(self) -> tuple[bool, str]:
        """Walk the chain; return (is_intact, message).

        Reports the FIRST broken point. Three independent checks per entry:
        * ``seq`` is contiguous           -> catches deletion / insertion / reordering
        * ``prev_hash`` links to previous -> catches deletion / reordering
        * ``hash`` matches the contents   -> catches in-place edits
        """
        expected_prev = GENESIS_HASH
        count = 0
        try:
            entries = self.entries()
        except json.JSONDecodeError as exc:
            return False, f"audit log is not valid JSON-lines (line {exc.lineno}): corrupted"

        for position, entry in enumerate(entries):
            seq = entry.get("seq")
            if seq != position:
                return False, (
                    f"chain broken at position {position}: expected seq={position} but "
                    f"found seq={seq} (an entry was deleted, inserted or reordered)"
                )
            if entry.get("prev_hash") != expected_prev:
                return False, (
                    f"chain broken at seq={seq}: prev_hash does not match the hash of "
                    f"seq={seq - 1} (an entry was deleted, inserted or reordered, or seq={seq - 1} "
                    f"was rewritten together with its hash)"
                )
            body = {k: v for k, v in entry.items() if k != "hash"}
            if compute_hash(body) != entry.get("hash"):
                return False, (
                    f"chain broken at seq={seq}: stored hash does not match the entry's "
                    f"contents (entry seq={seq} was modified)"
                )
            expected_prev = entry["hash"]
            count += 1

        if count == 0:
            return True, "audit log is empty (trivially intact)"
        return True, f"audit log intact: {count} entries, head hash {expected_prev[:16]}..."
