"""Rule-based insider-threat detection over the audit trail.

Input: audit events only (metadata: who, when, which columns, outcome, row
counts). The detector never sees decrypted values, so it can run with far less
privilege than the data it protects.

Why rules and not ML: every alert must be explainable to a human investigator
("this user pulled 12 rows when they normally pull ~4"), the rules are easy to
test exhaustively, and there is no training data to poison. The trade-off — an
attacker who knows the thresholds can stay under them — is documented in
docs/threat-model.md.

Rules (all evaluated per user, in log order, using only PRIOR events as history):

1. VOLUME_SPIKE        requested rows > max(mean + 3*stdev, 2*mean) of the user's
                       recent history (needs a minimum history first).
2. NEW_SENSITIVE_COLUMN a sensitive column the user never requested in any prior
                       event. A user's very first sensitive access is not flagged
                       (no baseline yet) and columns in the same event are not
                       "prior" to each other.
3. DENY_BURST          >= 3 denied queries within the user's last N queries.
4. OFF_HOURS           sensitive-column access outside working hours / on weekends.
"""

from __future__ import annotations

import statistics
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence

from security.policy import SENSITIVE_COLUMNS


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


_SEVERITY_ORDER = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2}


@dataclass(frozen=True)
class Alert:
    rule: str
    severity: Severity
    user: str
    seq: int  # audit sequence number of the triggering event
    ts: str
    reason: str  # plain-English, specific; no opaque scores

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule, "severity": self.severity.value, "user": self.user,
            "seq": self.seq, "ts": self.ts, "reason": self.reason,
        }


@dataclass(frozen=True)
class DetectionConfig:
    # Volume spike
    volume_window: int = 20          # how many prior queries form the baseline
    volume_min_history: int = 3      # no baseline -> no verdict
    volume_stdev_factor: float = 3.0
    volume_min_ratio: float = 2.0    # floor so zero-variance baselines don't over-fire
    # Deny burst
    deny_window: int = 5             # the user's last N queries (sequence window)
    deny_threshold: int = 3
    # Off-hours (evaluated in UTC; a real deployment would use the user's timezone)
    work_start_hour: int = 8         # inclusive
    work_end_hour: int = 19          # exclusive
    weekend_is_off_hours: bool = True
    # Columns whose first-time access is treated as high severity
    high_risk_columns: frozenset[str] = field(default_factory=lambda: frozenset({"ssn"}))


def _sensitive_in(event: Mapping[str, Any], sensitive: frozenset[str]) -> list[str]:
    return [c for c in event.get("columns", []) if c in sensitive]


def _plaintext_revealed(event: Mapping[str, Any], cols: Iterable[str]) -> bool:
    if event.get("outcome") not in {"served", "masked"} or int(event.get("row_count", 0)) == 0:
        return False
    decisions = event.get("decisions", {})
    return any(decisions.get(c, {}).get("effect") == "ALLOW" for c in cols)


def detect(
    events: Sequence[Mapping[str, Any]],
    sensitive_columns: Iterable[str] = SENSITIVE_COLUMNS,
    config: DetectionConfig = DetectionConfig(),
) -> list[Alert]:
    """Run all rules over ``events`` (oldest first) and return alerts in log order."""
    sensitive = frozenset(sensitive_columns)
    alerts: list[Alert] = []

    volume_hist: dict[str, deque[int]] = defaultdict(lambda: deque(maxlen=config.volume_window))
    seen_cols: dict[str, set[str]] = defaultdict(set)
    recent_outcomes: dict[str, deque[tuple[int, str]]] = defaultdict(
        lambda: deque(maxlen=config.deny_window)
    )
    last_burst_alert_seq: dict[str, int] = {}

    for ev in events:
        user, seq, ts = ev["user"], int(ev["seq"]), ev["ts"]
        sens_cols = _sensitive_in(ev, sensitive)
        rows = int(ev.get("requested_row_count", ev.get("row_count", 0)))

        # --- 1. Volume spike (baseline = this user's PRIOR queries only) -------- #
        hist = volume_hist[user]
        if len(hist) >= config.volume_min_history:
            mean = statistics.fmean(hist)
            stdev = statistics.pstdev(hist)
            threshold = max(mean + config.volume_stdev_factor * stdev, config.volume_min_ratio * mean)
            if rows > threshold:
                sev = Severity.HIGH if sens_cols else Severity.MEDIUM
                alerts.append(Alert(
                    "VOLUME_SPIKE", sev, user, seq, ts,
                    f"{user} requested {rows} rows; their last {len(hist)} queries averaged "
                    f"{mean:.1f} rows (stdev {stdev:.1f}), threshold {threshold:.1f}. "
                    f"Outcome: {ev.get('outcome')}. Columns: {', '.join(ev.get('columns', []))}.",
                ))
        hist.append(rows)

        # --- 2. New sensitive column (history = PRIOR events only) ------------- #
        prior = seen_cols[user]
        new_cols = [c for c in sens_cols if c not in prior]
        if prior and new_cols:  # empty prior => first-ever sensitive access: no baseline
            sev = (
                Severity.HIGH if any(c in config.high_risk_columns for c in new_cols)
                else Severity.MEDIUM
            )
            alerts.append(Alert(
                "NEW_SENSITIVE_COLUMN", sev, user, seq, ts,
                f"{user} requested sensitive column(s) {', '.join(new_cols)} for the first "
                f"time; previously only touched {', '.join(sorted(prior))}. "
                f"Outcome: {ev.get('outcome')}.",
            ))
        prior.update(sens_cols)  # update AFTER the check: same-event columns aren't "prior"

        # --- 3. Deny burst (sequence window over the user's own queries) ------- #
        window = recent_outcomes[user]
        window.append((seq, ev.get("outcome", "")))
        if ev.get("outcome") == "denied":
            denied_seqs = [s for s, o in window if o == "denied"]
            already = last_burst_alert_seq.get(user)
            # One alert per burst: suppress while the previous alert is still in the window.
            if len(denied_seqs) >= config.deny_threshold and (
                already is None or already not in {s for s, _ in window}
            ):
                last_burst_alert_seq[user] = seq
                alerts.append(Alert(
                    "DENY_BURST", Severity.HIGH, user, seq, ts,
                    f"{user} had {len(denied_seqs)} denied queries within their last "
                    f"{len(window)} queries (audit seq {', '.join(map(str, denied_seqs))}) "
                    f"— consistent with probing for data they are not entitled to.",
                ))

        # --- 4. Off-hours sensitive access ------------------------------------ #
        if sens_cols:
            when = datetime.fromisoformat(ts)
            weekend = config.weekend_is_off_hours and when.weekday() >= 5
            outside = not (config.work_start_hour <= when.hour < config.work_end_hour)
            if weekend or outside:
                revealed = _plaintext_revealed(ev, sens_cols)
                sev = Severity.MEDIUM if revealed else Severity.LOW
                why = "on a weekend" if weekend else (
                    f"outside working hours {config.work_start_hour:02d}:00-"
                    f"{config.work_end_hour:02d}:00 UTC"
                )
                alerts.append(Alert(
                    "OFF_HOURS", sev, user, seq, ts,
                    f"{user} accessed sensitive column(s) {', '.join(sens_cols)} at "
                    f"{when.strftime('%a %Y-%m-%d %H:%M')} UTC, {why}. "
                    f"Outcome: {ev.get('outcome')}"
                    f"{' (plaintext returned)' if revealed else ''}.",
                ))

    return alerts


def summarize(alerts: Sequence[Alert]) -> dict[str, int]:
    """Count alerts per severity (used by CLI/dashboard)."""
    counts = {s.value: 0 for s in sorted(Severity, key=_SEVERITY_ORDER.get, reverse=True)}
    for a in alerts:
        counts[a.severity.value] += 1
    return counts
