"""Rule-based insider-threat detection over synthetic audit events."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from security.anomaly import DetectionConfig, Severity, detect, summarize

WORKDAY = datetime(2026, 11, 10, 10, 0, tzinfo=timezone.utc)  # Tuesday 10:00


class EventFactory:
    """Builds audit-shaped events with increasing seq / timestamps."""

    def __init__(self) -> None:
        self.seq = 0
        self.t = WORKDAY

    def __call__(self, user="sam", columns=("employee_id",), outcome="served", rows=4,
                 at: datetime | None = None, effect="ALLOW") -> dict:
        ev = {
            "seq": self.seq,
            "ts": (at or self.t).isoformat(),
            "user": user,
            "columns": list(columns),
            "decisions": {c: {"effect": "DENY" if outcome == "denied" else effect} for c in columns},
            "outcome": outcome,
            "row_count": 0 if outcome == "denied" else rows,
            "requested_row_count": rows,
        }
        self.seq += 1
        self.t += timedelta(minutes=10)
        return ev


def rules(alerts, rule):
    return [a for a in alerts if a.rule == rule]


# --- volume spike ---------------------------------------------------------- #
def test_volume_spike_detected():
    ev = EventFactory()
    events = [ev(rows=4), ev(rows=5), ev(rows=4), ev(rows=3), ev(rows=500, columns=["salary"])]
    spikes = rules(detect(events), "VOLUME_SPIKE")
    assert len(spikes) == 1
    assert spikes[0].seq == 4
    assert spikes[0].severity is Severity.HIGH  # touched a sensitive column
    assert "500 rows" in spikes[0].reason and "averaged 4.0" in spikes[0].reason


def test_volume_spike_not_triggered_on_consistent_usage():
    ev = EventFactory()
    events = [ev(rows=r) for r in (10, 12, 11, 10, 12, 11, 13, 10, 12, 11)]
    assert rules(detect(events), "VOLUME_SPIKE") == []


def test_volume_spike_zero_variance_baseline_needs_meaningful_jump():
    ev = EventFactory()
    events = [ev(rows=4) for _ in range(5)] + [ev(rows=5)]
    # stdev == 0 would make mean+3*stdev == 4; the 2x floor prevents a 4->5 alert.
    assert rules(detect(events), "VOLUME_SPIKE") == []


def test_volume_spike_needs_minimum_history():
    ev = EventFactory()
    assert rules(detect([ev(rows=1), ev(rows=1000)]), "VOLUME_SPIKE") == []


def test_volume_baseline_is_per_user():
    ev = EventFactory()
    events = [ev(user="small", rows=2) for _ in range(4)] + [ev(user="big", rows=1000) for _ in range(4)]
    assert rules(detect(events), "VOLUME_SPIKE") == []


# --- new sensitive column ---------------------------------------------------- #
def test_first_ever_sensitive_access_not_flagged():
    ev = EventFactory()
    events = [ev(columns=["employee_id"]), ev(columns=["employee_id", "name", "salary"])]
    assert rules(detect(events), "NEW_SENSITIVE_COLUMN") == []


def test_columns_in_same_event_are_not_prior_for_each_other():
    ev = EventFactory()
    # name and salary arrive together in the user's first sensitive event:
    # neither may be treated as "history" for the other.
    assert rules(detect([ev(columns=["name", "salary"])]), "NEW_SENSITIVE_COLUMN") == []


def test_next_new_sensitive_column_is_flagged():
    ev = EventFactory()
    events = [ev(columns=["name", "salary"]), ev(columns=["salary"]), ev(columns=["salary", "email"])]
    alerts = rules(detect(events), "NEW_SENSITIVE_COLUMN")
    assert len(alerts) == 1
    assert alerts[0].seq == 2
    assert "email" in alerts[0].reason and "name, salary" in alerts[0].reason
    assert alerts[0].severity is Severity.MEDIUM


def test_new_ssn_access_is_high_severity_even_if_denied():
    ev = EventFactory()
    events = [ev(columns=["name"]), ev(columns=["ssn"], outcome="denied")]
    [alert] = rules(detect(events), "NEW_SENSITIVE_COLUMN")
    assert alert.severity is Severity.HIGH and "ssn" in alert.reason


def test_non_sensitive_columns_never_trigger_new_column():
    ev = EventFactory()
    events = [ev(columns=["name"]), ev(columns=["employee_id", "department"])]
    assert rules(detect(events), "NEW_SENSITIVE_COLUMN") == []


# --- deny burst ---------------------------------------------------------------- #
def test_deny_burst_detected():
    ev = EventFactory()
    events = [ev(), ev(outcome="denied"), ev(outcome="denied"), ev(outcome="denied")]
    [alert] = rules(detect(events), "DENY_BURST")
    assert alert.seq == 3 and alert.severity is Severity.HIGH
    assert "3 denied" in alert.reason


def test_deny_burst_alerts_once_per_burst():
    ev = EventFactory()
    events = [ev(outcome="denied") for _ in range(5)]
    assert len(rules(detect(events), "DENY_BURST")) == 1


def test_spread_out_denials_do_not_trigger_burst():
    ev = EventFactory()
    events = []
    for _ in range(3):
        events += [ev(outcome="denied")] + [ev() for _ in range(5)]
    assert rules(detect(events), "DENY_BURST") == []


def test_deny_burst_is_per_user():
    ev = EventFactory()
    events = [ev(user=u, outcome="denied") for u in ("a", "b", "c")]
    assert rules(detect(events), "DENY_BURST") == []


# --- off hours ------------------------------------------------------------------ #
def test_off_hours_detected():
    ev = EventFactory()
    night = datetime(2026, 11, 10, 23, 40, tzinfo=timezone.utc)
    [alert] = rules(detect([ev(columns=["salary"], at=night)]), "OFF_HOURS")
    assert alert.severity is Severity.MEDIUM  # plaintext was returned
    assert "23:40" in alert.reason and "outside working hours" in alert.reason


def test_off_hours_weekend_detected():
    ev = EventFactory()
    saturday_noon = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)
    [alert] = rules(detect([ev(columns=["ssn"], at=saturday_noon)]), "OFF_HOURS")
    assert "weekend" in alert.reason


def test_off_hours_masked_or_denied_is_low_severity():
    ev = EventFactory()
    night = datetime(2026, 11, 10, 2, 0, tzinfo=timezone.utc)
    [alert] = rules(detect([ev(columns=["ssn"], outcome="denied", at=night)]), "OFF_HOURS")
    assert alert.severity is Severity.LOW


def test_business_hours_and_non_sensitive_not_flagged():
    ev = EventFactory()
    night = datetime(2026, 11, 10, 23, 0, tzinfo=timezone.utc)
    events = [ev(columns=["salary"]), ev(columns=["employee_id"], at=night)]
    assert rules(detect(events), "OFF_HOURS") == []


def test_working_hours_boundaries():
    ev = EventFactory()
    cfg = DetectionConfig()
    at_start = WORKDAY.replace(hour=cfg.work_start_hour, minute=0)
    at_end = WORKDAY.replace(hour=cfg.work_end_hour, minute=0)
    alerts = rules(detect([ev(columns=["name"], at=at_start), ev(columns=["name"], at=at_end)]), "OFF_HOURS")
    assert [a.seq for a in alerts] == [1]  # start inclusive, end exclusive


# --- general ------------------------------------------------------------------- #
def test_every_alert_is_explained_and_summarized():
    ev = EventFactory()
    night = datetime(2026, 11, 10, 23, 0, tzinfo=timezone.utc)
    events = [ev(columns=["name"]) for _ in range(3)] + [
        ev(columns=["ssn"], outcome="denied", rows=50, at=night) for _ in range(3)
    ]
    alerts = detect(events)
    assert {a.rule for a in alerts} == {"VOLUME_SPIKE", "NEW_SENSITIVE_COLUMN", "DENY_BURST", "OFF_HOURS"}
    assert all(a.reason and a.user == "sam" for a in alerts)
    assert sum(summarize(alerts).values()) == len(alerts)


def test_empty_trail_has_no_alerts():
    assert detect([]) == []
