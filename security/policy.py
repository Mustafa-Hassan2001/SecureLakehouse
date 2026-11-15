"""Hybrid RBAC + ABAC column-level access-control engine.

RBAC part: every column has a :class:`ColumnRule` naming which roles see the real
value (ALLOW) and which see a redacted placeholder (MASK). Every other role gets
DENY. A column with *no rule at all* is DENY for everyone (default-deny: forgetting
to write a rule must fail safe, never leak).

ABAC part: two attribute-based conditions refine an ALLOW decision:

* ``department_scoped`` — the caller only sees rows whose ``department`` equals
  their own ``Subject.department`` attribute (row-level security).
* ``max_rows_per_query`` — if the query would return more rows than this, the
  column is DENIED outright. This is the primary bulk-exfiltration control: a
  compromised analyst account can still read a handful of rows, but cannot dump
  the table.

Design decision: ABAC conditions apply only where *plaintext would be revealed*
(ALLOW) and only to non-privileged roles. A MASKed value reveals nothing, so
scoping or capping it adds no protection. ``admin`` is privileged (bypasses the
ABAC conditions) but — like everyone — is still fully audited and is still
watched by the anomaly detector.

The engine is a pure function of (policy, subject, column, row count); it never
touches data, which makes it trivial to unit-test exhaustively.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping, Optional

ROLES: frozenset[str] = frozenset({"admin", "analyst", "auditor", "support"})

#: Columns that are encrypted at rest and treated as sensitive by the detector.
SENSITIVE_COLUMNS: tuple[str, ...] = ("name", "email", "ssn", "salary")

#: Column used for department-scoped row filters.
DEPARTMENT_COLUMN = "department"


class Effect(str, Enum):
    """Per-column decision. Inherits ``str`` so it serializes cleanly into the audit log."""

    ALLOW = "ALLOW"
    MASK = "MASK"
    DENY = "DENY"


@dataclass(frozen=True)
class Subject:
    """The caller. Authentication is out of scope: these attributes are assumed to
    come from a trusted identity provider (see docs/threat-model.md)."""

    user_id: str
    role: str
    department: str


@dataclass(frozen=True)
class RowFilter:
    """An equality row filter, e.g. ``department == 'Engineering'``."""

    column: str
    value: str

    def describe(self) -> str:
        return f"{self.column} == {self.value!r}"


@dataclass(frozen=True)
class Decision:
    effect: Effect
    reason: str
    row_filter: Optional[RowFilter] = None


@dataclass(frozen=True)
class ColumnRule:
    allow: frozenset[str] = frozenset()
    mask: frozenset[str] = frozenset()
    department_scoped: bool = False
    max_rows_per_query: Optional[int] = None

    def __post_init__(self) -> None:
        overlap = self.allow & self.mask
        if overlap:
            raise ValueError(f"roles cannot be both ALLOW and MASK: {sorted(overlap)}")


@dataclass(frozen=True)
class Policy:
    """A set of column rules plus the roles that bypass ABAC conditions."""

    rules: Mapping[str, ColumnRule]
    privileged_roles: frozenset[str] = field(default_factory=lambda: frozenset({"admin"}))

    # ------------------------------------------------------------------ #
    def row_filter_for(self, subject: Subject, column: str) -> Optional[RowFilter]:
        """The row filter that applies if ``subject`` reads ``column`` (or None).

        Exposed separately because the gateway needs the filters *before* it can
        count rows, and the count is an input to :meth:`decide`.
        """
        rule = self.rules.get(column)
        if (
            rule is not None
            and rule.department_scoped
            and subject.role in rule.allow
            and subject.role not in self.privileged_roles
        ):
            return RowFilter(DEPARTMENT_COLUMN, subject.department)
        return None

    def decide(self, subject: Subject, column: str, requested_row_count: int) -> Decision:
        """Decide ALLOW / MASK / DENY for one column of one query.

        ``requested_row_count`` is the number of rows the query would return after
        row-level filters are applied.
        """
        if subject.role not in ROLES:
            return Decision(Effect.DENY, f"unknown role {subject.role!r} (default-deny)")

        rule = self.rules.get(column)
        if rule is None:
            return Decision(Effect.DENY, f"no policy rule for column {column!r} (default-deny)")

        if subject.role in rule.mask:
            return Decision(Effect.MASK, f"role {subject.role!r} may only see {column!r} redacted")

        if subject.role not in rule.allow:
            return Decision(Effect.DENY, f"role {subject.role!r} has no access to {column!r}")

        # ALLOW by role — now apply ABAC conditions for non-privileged roles.
        privileged = subject.role in self.privileged_roles
        cap = rule.max_rows_per_query
        if cap is not None and not privileged and requested_row_count > cap:
            return Decision(
                Effect.DENY,
                f"query would return {requested_row_count} rows of {column!r}, "
                f"exceeding the per-query cap of {cap} for role {subject.role!r}",
            )

        row_filter = self.row_filter_for(subject, column)
        if row_filter is not None:
            return Decision(
                Effect.ALLOW,
                f"role {subject.role!r} allowed, scoped to {row_filter.describe()}",
                row_filter,
            )
        return Decision(Effect.ALLOW, f"role {subject.role!r} allowed")


def default_policy() -> Policy:
    """The policy used by the demo, CLI and dashboard.

    | column      | admin | analyst                 | support | auditor |
    |-------------|-------|-------------------------|---------|---------|
    | employee_id | ALLOW | ALLOW                   | ALLOW   | ALLOW   |
    | department  | ALLOW | ALLOW                   | ALLOW   | ALLOW   |
    | name        | ALLOW | ALLOW (cap 5)           | ALLOW (cap 5) | MASK |
    | email       | ALLOW | MASK                    | ALLOW (cap 5) | MASK |
    | ssn         | ALLOW | DENY                    | MASK    | MASK    |
    | salary      | ALLOW | ALLOW (own dept, cap 5) | DENY    | MASK    |
    """
    everyone = ROLES
    return Policy(
        rules={
            "employee_id": ColumnRule(allow=everyone),
            "department": ColumnRule(allow=everyone),
            "name": ColumnRule(
                allow=frozenset({"admin", "analyst", "support"}),
                mask=frozenset({"auditor"}),
                max_rows_per_query=5,
            ),
            "email": ColumnRule(
                allow=frozenset({"admin", "support"}),
                mask=frozenset({"analyst", "auditor"}),
                max_rows_per_query=5,
            ),
            "ssn": ColumnRule(
                allow=frozenset({"admin"}),
                mask=frozenset({"support", "auditor"}),
            ),
            "salary": ColumnRule(
                allow=frozenset({"admin", "analyst"}),
                mask=frozenset({"auditor"}),
                department_scoped=True,
                max_rows_per_query=5,
            ),
        }
    )
