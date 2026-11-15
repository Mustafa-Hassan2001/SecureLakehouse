"""RBAC + ABAC policy engine (pure functions, no Spark)."""

from __future__ import annotations

import pytest

from security.policy import ColumnRule, Effect, Policy, RowFilter, Subject, default_policy

POLICY = default_policy()
ADMIN = Subject("a", "admin", "IT")
ANALYST = Subject("b", "analyst", "Engineering")
AUDITOR = Subject("c", "auditor", "Compliance")
SUPPORT = Subject("d", "support", "HR")

# Expected effect for every (role, column) pair at a small row count (no cap hit).
EXPECTED = {
    "admin":   {"employee_id": "ALLOW", "department": "ALLOW", "name": "ALLOW", "email": "ALLOW", "ssn": "ALLOW", "salary": "ALLOW"},
    "analyst": {"employee_id": "ALLOW", "department": "ALLOW", "name": "ALLOW", "email": "MASK",  "ssn": "DENY",  "salary": "ALLOW"},
    "support": {"employee_id": "ALLOW", "department": "ALLOW", "name": "ALLOW", "email": "ALLOW", "ssn": "MASK",  "salary": "DENY"},
    "auditor": {"employee_id": "ALLOW", "department": "ALLOW", "name": "MASK",  "email": "MASK",  "ssn": "MASK",  "salary": "MASK"},
}


@pytest.mark.parametrize(
    "subject,column",
    [(s, c) for s in (ADMIN, ANALYST, AUDITOR, SUPPORT) for c in EXPECTED["admin"]],
    ids=lambda x: x.role if isinstance(x, Subject) else x,
)
def test_role_column_matrix(subject, column):
    decision = POLICY.decide(subject, column, requested_row_count=1)
    assert decision.effect.value == EXPECTED[subject.role][column], decision.reason
    assert decision.reason  # every decision explains itself


@pytest.mark.parametrize("subject", [ADMIN, ANALYST, AUDITOR, SUPPORT], ids=lambda s: s.role)
def test_unknown_column_default_denies(subject):
    d = POLICY.decide(subject, "password_hash", 1)
    assert d.effect is Effect.DENY
    assert "default-deny" in d.reason


def test_physical_ciphertext_column_is_default_denied():
    assert POLICY.decide(ADMIN, "ssn_enc", 1).effect is Effect.DENY


def test_unknown_role_default_denies():
    d = POLICY.decide(Subject("x", "superuser", "IT"), "employee_id", 1)
    assert d.effect is Effect.DENY


def test_empty_policy_denies_everything():
    assert Policy(rules={}).decide(ADMIN, "employee_id", 1).effect is Effect.DENY


def test_row_cap_triggers_deny():
    assert POLICY.decide(ANALYST, "name", 5).effect is Effect.ALLOW  # at the cap: fine
    d = POLICY.decide(ANALYST, "name", 6)
    assert d.effect is Effect.DENY
    assert "cap of 5" in d.reason


def test_row_cap_does_not_apply_to_privileged_role():
    assert POLICY.decide(ADMIN, "name", 10_000).effect is Effect.ALLOW


def test_row_cap_does_not_apply_to_masked_values():
    # Masked output reveals nothing, so capping it adds no protection.
    assert POLICY.decide(AUDITOR, "name", 10_000).effect is Effect.MASK


def test_department_scoping_produces_row_filter():
    d = POLICY.decide(ANALYST, "salary", 3)
    assert d.effect is Effect.ALLOW
    assert d.row_filter == RowFilter("department", "Engineering")
    assert POLICY.row_filter_for(ANALYST, "salary") == RowFilter("department", "Engineering")


def test_department_scoping_follows_caller_attribute():
    other = Subject("e", "analyst", "Finance")
    assert POLICY.decide(other, "salary", 1).row_filter == RowFilter("department", "Finance")


def test_no_row_filter_for_admin_or_unscoped_columns():
    assert POLICY.decide(ADMIN, "salary", 1).row_filter is None
    assert POLICY.decide(ANALYST, "name", 1).row_filter is None
    assert POLICY.row_filter_for(AUDITOR, "salary") is None  # masked -> no scoping needed


def test_rule_cannot_both_allow_and_mask_a_role():
    with pytest.raises(ValueError):
        ColumnRule(allow=frozenset({"analyst"}), mask=frozenset({"analyst"}))
