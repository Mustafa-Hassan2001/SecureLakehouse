"""SecureLakehouse — Streamlit dashboard (presentation layer only).

SEPARATION OF CONCERNS — read this first:
This file contains NO security logic. Every query goes through the same
``SecureGateway`` (pipeline/gateway.py), every event is written and verified by
the same ``AuditLog`` (security/audit.py), and alerts come from the same
``anomaly.detect()`` (security/anomaly.py) that the CLI and the demo use; the
components are wired by the shared ``pipeline.context.open_lakehouse``. The UI
never reads Parquet directly, never touches key material, never decides access
and never computes hashes. If this file were deleted, the security properties of
the system would be unchanged. Choosing a role in the sidebar stands in for an
identity provider (authentication is explicitly out of scope).

Run:  SECURELAKEHOUSE_PASSPHRASE='...' streamlit run app.py
"""

from __future__ import annotations

import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

from demo.scenario import BREACH_STEPS, LEGIT_STEPS, SimulatedClock, run_steps, simulate_tampering
from pipeline.context import PASSPHRASE_ENV, audit_path, open_lakehouse
from pipeline.ingest import ingest_csv
from security import anomaly
from security.policy import ROLES, SENSITIVE_COLUMNS, Subject

ROOT = Path(__file__).resolve().parent
WORKSPACE = ROOT / "app_workspace"
LAKE, STATE = WORKSPACE / "lake", WORKSPACE / "state"
SAMPLE_CSV = ROOT / "data" / "raw" / "employees.csv"
ALL_COLUMNS = ["employee_id", "department", "name", "email", "ssn", "salary"]
SEVERITY_STYLE = {"HIGH": st.error, "MEDIUM": st.warning, "LOW": st.info}
EFFECT_COLOR = {"ALLOW": "#1b7f3b", "MASK": "#b07d00", "DENY": "#b3261e"}


class AppClock(SimulatedClock):
    """Real UTC time, except while the scripted scenario replays simulated times."""

    def __init__(self) -> None:
        self.now = None  # type: ignore[assignment]

    def __call__(self) -> datetime:
        return self.now or datetime.now(timezone.utc)


@st.cache_resource(show_spinner="Starting Spark and opening the keystore...")
def get_lakehouse(passphrase: str):
    clock = AppClock()
    return open_lakehouse(LAKE, STATE, passphrase, clock=clock), clock


def lake_ready() -> bool:
    return (LAKE / "_securelakehouse_meta.json").exists()


# --------------------------------------------------------------------------- #
st.set_page_config(page_title="SecureLakehouse", layout="wide")
st.title("SecureLakehouse")
st.caption("Column-level encryption · RBAC/ABAC gateway · hash-chained audit log · "
           "insider-threat rules — all enforced below the UI.")

passphrase = os.environ.get(PASSPHRASE_ENV) or st.sidebar.text_input(
    "Keystore passphrase", type="password",
    help=f"Or set {PASSPHRASE_ENV}. Derives the master key; never stored.")
if not passphrase:
    st.info("Enter the keystore passphrase in the sidebar to start.")
    st.stop()

try:
    lh, clock = get_lakehouse(passphrase)
except PermissionError as exc:
    st.error(f"Cannot open keystore: {exc}")
    st.stop()

# --- Sidebar: identity + workspace ---------------------------------------- #
st.sidebar.header("Caller identity")
role = st.sidebar.selectbox("Role", sorted(ROLES), index=sorted(ROLES).index("analyst"))
user = st.sidebar.text_input("User", value=f"demo.{role}")
department = st.sidebar.selectbox("Department", ["Engineering", "Finance", "Sales", "HR", "IT", "Compliance"])

st.sidebar.header("Workspace")
st.sidebar.caption(f"`{WORKSPACE.relative_to(ROOT)}/` (lake, keystore, audit log)")
if st.sidebar.button("Reset workspace & ingest sample CSV"):
    shutil.rmtree(LAKE, ignore_errors=True)
    audit_path(STATE).unlink(missing_ok=True)
    n = ingest_csv(lh.spark, SAMPLE_CSV, LAKE, lh.key_manager)
    st.sidebar.success(f"Ingested {n} encrypted rows.")

if not lake_ready():
    st.warning("No lake yet — click **Reset workspace & ingest sample CSV** in the sidebar.")
    st.stop()

# --- Query ----------------------------------------------------------------- #
st.header("Query the lake")
c1, c2 = st.columns([3, 2])
columns = c1.multiselect("Columns", ALL_COLUMNS, default=["employee_id", "name", "salary"])
fcol = c2.selectbox("Optional filter column", ["(none)", "employee_id", "department"])
fval = c2.text_input("Filter value", disabled=fcol == "(none)")

if st.button("Run query", type="primary"):
    filters = {fcol: fval} if fcol != "(none)" and fval else None
    result = lh.gateway.query(Subject(user, role, department), columns, filters)
    st.session_state["last_result"] = result

result = st.session_state.get("last_result")
if result is not None:
    st.subheader(f"Outcome: {result.outcome.upper()}  ·  audit seq {result.audit_seq}")
    for col, d in result.decisions.items():
        st.markdown(
            f"<span style='color:{EFFECT_COLOR[d.effect.value]};font-weight:600'>"
            f"{d.effect.value}</span> &nbsp;`{col}` — {d.reason}", unsafe_allow_html=True)
    if result.outcome == "denied":
        st.error(result.reason)
    else:
        st.dataframe(pd.DataFrame(result.rows, columns=result.columns), width="stretch")

# --- Breach simulation ----------------------------------------------------- #
st.header("Breach simulation")
st.caption("Replays the scripted scenario (simulated Tue 2026-11-10): a normal workday, "
           "then sam.analyst's account probing for SSNs and bulk-exporting at 23:40.")
if st.button("Run breach simulation"):
    log: list[dict] = []
    try:
        run_steps(lh.gateway, clock, LEGIT_STEPS + BREACH_STEPS,
                  lambda s, r: log.append({"time": s.at.strftime("%H:%M"), "user": s.subject.user_id,
                                           "role": s.subject.role, "columns": ", ".join(s.columns),
                                           "outcome": r.outcome, "reason": r.reason}))
    finally:
        clock.now = None  # back to real time
    st.dataframe(pd.DataFrame(log), width="stretch", hide_index=True)

# --- Alerts ---------------------------------------------------------------- #
st.header("Insider-threat alerts")
events = lh.audit.entries()
alerts = anomaly.detect(events, SENSITIVE_COLUMNS)
st.write(f"{len(events)} audit events analysed → {len(alerts)} alerts {anomaly.summarize(alerts)}")
for a in sorted(alerts, key=lambda a: ({"HIGH": 0, "MEDIUM": 1, "LOW": 2}[a.severity.value], a.seq)):
    SEVERITY_STYLE[a.severity.value](f"**{a.severity.value} · {a.rule}** (seq {a.seq}) — {a.reason}")

# --- Audit log ------------------------------------------------------------- #
st.header("Audit log")
b1, b2, _ = st.columns([1, 1, 3])
if b1.button("Verify integrity"):
    ok, msg = lh.audit.verify()
    (st.success if ok else st.error)(("INTACT — " if ok else "TAMPERED — ") + msg)
if b2.button("Simulate tampering"):
    if events:
        target = next((e for e in events if e["outcome"] == "denied"), events[0])
        simulate_tampering(audit_path(STATE), target["seq"], {"outcome": "served"})
        st.warning(f"Attacker rewrote seq={target['seq']} ('{target['outcome']}' → 'served'). "
                   "Click **Verify integrity**.")
        events = lh.audit.entries()
    else:
        st.info("The audit log is empty — run a query first.")

if events:
    st.dataframe(
        pd.DataFrame([{
            "seq": e["seq"], "ts": e["ts"], "user": e["user"], "role": e["role"],
            "columns": ", ".join(e["columns"]), "outcome": e["outcome"],
            "rows": e["row_count"], "requested": e["requested_row_count"],
            "reason": e["reason"], "hash": e["hash"][:12] + "…",
            "prev_hash": e["prev_hash"][:12] + "…",
        } for e in reversed(events)]),
        width="stretch", hide_index=True,
    )
