"""SecureGateway — the only supported read path into the lake.

Per query:

1. Validate optional equality filters (only on plaintext columns the caller may read).
2. Collect ABAC row filters (department scoping) for the requested columns.
3. Count the rows the query would return, then ask the policy engine for a
   decision per column, given that count.
4. If ANY column is DENY -> refuse the WHOLE query (fail closed). Partial results
   would let a caller learn which columns exist / which are sensitive by probing.
5. Otherwise decrypt only ALLOWed sensitive columns (broadcast-safe, see below),
   replace MASKed columns with a constant redaction (no key is ever used for a
   masked column, so the mask cannot be reversed), and collect the result.
6. Write exactly ONE audit event — for served, masked, denied and error outcomes.

Broadcast-safe decryption: key bytes for the ALLOWed columns only (least
privilege) are resolved on the driver and broadcast; the UDF uses only those
bytes. The broadcast is destroyed as soon as the result has been collected.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence

from pyspark.sql import Column, SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import StringType

from pipeline.ingest import read_lake_meta
from security.audit import AuditLog
from security.crypto import KeyManager, decrypt_with_key
from security.policy import Decision, Effect, Policy, RowFilter, Subject

#: Constant placeholder for MASKed cells. It is the same for every cell, so it
#: leaks nothing — not even length, unlike partial masks such as ``***-**-1234``.
REDACTED = "***REDACTED***"


@dataclass
class QueryResult:
    outcome: str  # served | masked | denied
    columns: list[str]
    rows: list[dict[str, Any]]
    decisions: dict[str, Decision]
    reason: str
    audit_seq: int
    row_filters: list[RowFilter] = field(default_factory=list)

    @property
    def row_count(self) -> int:
        return len(self.rows)


def make_decrypt_udf(key_broadcast, column: str):
    """UDF that decrypts ``column`` with broadcast key bytes, choosing the key by
    each row's stored version (``<col>_kv``) so rotated data stays readable."""

    def _decrypt(token, version):  # no hints: see make_encrypt_udf in ingest.py
        if token is None:
            return None
        return decrypt_with_key(key_broadcast.value[column][int(version)], token)

    return F.udf(_decrypt, StringType())


class SecureGateway:
    def __init__(
        self,
        spark: SparkSession,
        lake_path: str | os.PathLike[str],
        key_manager: KeyManager,
        policy: Policy,
        audit_log: AuditLog,
    ) -> None:
        self.spark = spark
        self.lake_path = str(lake_path)
        self.key_manager = key_manager
        self.policy = policy
        self.audit = audit_log

    # ------------------------------------------------------------------ #
    def query(
        self,
        subject: Subject,
        columns: Sequence[str],
        filters: Optional[Mapping[str, str]] = None,
    ) -> QueryResult:
        """Run one access-controlled query. Always writes exactly one audit event."""
        columns = list(dict.fromkeys(columns))  # de-duplicate, keep order
        filters = {k: str(v) for k, v in (filters or {}).items()}
        try:
            return self._query(subject, columns, filters)
        except Exception as exc:
            # Fail closed AND leave a trace: an error is still an access attempt.
            # _query writes its audit event as its very last step, so reaching this
            # handler means no event was written yet.
            self.audit.record(
                user=subject.user_id, role=subject.role, department=subject.department,
                columns=columns, filters=filters, decisions={}, outcome="error",
                row_count=0, requested_row_count=0,
                reason=f"gateway error, nothing returned: {type(exc).__name__}",
            )
            raise

    # ------------------------------------------------------------------ #
    def _deny(
        self,
        subject: Subject,
        columns: list[str],
        filters: dict[str, str],
        decisions: dict[str, Decision],
        requested_row_count: int,
        reason: str,
    ) -> QueryResult:
        entry = self.audit.record(
            user=subject.user_id, role=subject.role, department=subject.department,
            columns=columns, filters=filters, decisions=_serialize(decisions),
            outcome="denied", row_count=0, requested_row_count=requested_row_count,
            reason=reason,
        )
        return QueryResult("denied", columns, [], decisions, reason, entry["seq"])

    def _query(self, subject: Subject, columns: list[str], filters: dict[str, str]) -> QueryResult:
        if not columns:
            return self._deny(subject, columns, filters, {}, 0, "denied: no columns requested")

        meta = read_lake_meta(self.lake_path)
        logical_types: dict[str, str] = meta["logical_types"]
        sensitive: set[str] = set(meta["sensitive_columns"])

        # 1. Filters may only use plaintext columns the caller is ALLOWed to read;
        #    filtering on a column you cannot read would be an inference oracle.
        for fcol in filters:
            fdec = self.policy.decide(subject, fcol, 0)
            if fcol in sensitive or fcol not in logical_types or fdec.effect is not Effect.ALLOW:
                return self._deny(
                    subject, columns, filters, {}, 0,
                    f"denied: filtering on {fcol!r} is not permitted for role {subject.role!r}",
                )

        # 2. Row-level (ABAC) filters, then 3. count the rows the query would return.
        row_filters = list(
            dict.fromkeys(
                rf for c in columns if (rf := self.policy.row_filter_for(subject, c)) is not None
            )
        )
        df = self.spark.read.parquet(self.lake_path)
        for fcol, fval in filters.items():
            df = df.filter(F.col(fcol).cast("string") == F.lit(fval))
        for rf in row_filters:
            df = df.filter(F.col(rf.column) == F.lit(rf.value))
        n = df.count()

        decisions: dict[str, Decision] = {}
        for c in columns:
            d = self.policy.decide(subject, c, n)
            if d.effect is not Effect.DENY and c not in logical_types:
                d = Decision(Effect.DENY, f"column {c!r} does not exist in the lake")
            decisions[c] = d

        # 4. Fail closed: one denied column refuses the entire query.
        denied = {c: d for c, d in decisions.items() if d.effect is Effect.DENY}
        if denied:
            reason = "denied: " + "; ".join(f"{c}: {d.reason}" for c, d in denied.items())
            return self._deny(subject, columns, filters, decisions, n, reason)

        # 5. Decrypt only ALLOWed sensitive columns; keys for nothing else are shipped.
        allowed_sensitive = [
            c for c in columns if decisions[c].effect is Effect.ALLOW and c in sensitive
        ]
        material = self.key_manager.export_key_material(allowed_sensitive)
        bc = self.spark.sparkContext.broadcast(
            {c: dict(m.keys) for c, m in material.items()}
        )
        try:
            exprs: list[Column] = []
            for c in columns:
                if decisions[c].effect is Effect.MASK:
                    exprs.append(F.lit(REDACTED).alias(c))
                elif c in sensitive:
                    dec = make_decrypt_udf(bc, c)
                    exprs.append(
                        dec(F.col(f"{c}_enc"), F.col(f"{c}_kv")).cast(logical_types[c]).alias(c)
                    )
                else:
                    exprs.append(F.col(c).alias(c))
            if "employee_id" in df.columns:
                df = df.orderBy("employee_id")
            rows = [r.asDict() for r in df.select(*exprs).collect()]
        finally:
            bc.destroy()  # key bytes no longer needed on executors

        # 6. Exactly one audit event.
        outcome = "masked" if any(d.effect is Effect.MASK for d in decisions.values()) else "served"
        scope = f" with row filters [{', '.join(rf.describe() for rf in row_filters)}]" if row_filters else ""
        reason = f"{outcome}: {len(rows)} rows{scope}"
        entry = self.audit.record(
            user=subject.user_id, role=subject.role, department=subject.department,
            columns=columns, filters=filters, decisions=_serialize(decisions),
            outcome=outcome, row_count=len(rows), requested_row_count=n, reason=reason,
        )
        return QueryResult(outcome, columns, rows, decisions, reason, entry["seq"], row_filters)


def _serialize(decisions: Mapping[str, Decision]) -> dict[str, dict[str, str]]:
    return {c: {"effect": d.effect.value, "reason": d.reason} for c, d in decisions.items()}
