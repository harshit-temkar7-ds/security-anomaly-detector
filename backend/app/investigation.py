"""Transparent alert investigation: severity points, evidence and suggested next steps.

Everything here is derived from fields that actually exist on the event (and its
user-baseline result). Nothing is inferred from outside data: no IP reputation,
no geolocation, no claims about intent. Severity is a *triage priority*, not a
probability that an attack happened. The tool executes no remediation; steps are
suggestions that need an authorised human.
"""
from __future__ import annotations

from typing import Any, Optional

SEVERITY_BANDS = [("critical", 10), ("high", 7), ("medium", 4), ("low", 1)]
SEVERITY_ORDER = ["none", "low", "medium", "high", "critical"]
CONTEXT_FIELDS = ["event_id", "timestamp", "username", "source_ip"]

SEVERITY_POLICY = [
    {"factor": "model_score", "points": "2", "rule": "Isolation Forest score >= active threshold"},
    {"factor": "score_margin", "points": "1", "rule": "score exceeds threshold by >= 0.05"},
    {"factor": "rule_baseline", "points": "1", "rule": "failed_attempts >= 8, or new_device and country_changed both 1"},
    {"factor": "failed_attempts", "points": "2 / 1", "rule": ">= 8 / 5-7 failed attempts"},
    {"factor": "unique_ips_24h", "points": "1", "rule": ">= 4 distinct IPs in 24h"},
    {"factor": "device_location", "points": "2 / 1", "rule": "new device AND country changed / only one"},
    {"factor": "early_hours", "points": "1", "rule": "login_hour <= 5"},
    {"factor": "user_baseline", "points": "2 / 1", "rule": ">= 2 / 1 deviations from the user's own prior history"},
]
BANDS_TEXT = {"low": "1-3 points", "medium": "4-6", "high": "7-9", "critical": "10+"}


def band(points: int) -> str:
    for name, minimum in SEVERITY_BANDS:
        if points >= minimum:
            return name
    return "none"


def assess(data: dict[str, Any], score: float, threshold: float, rule_flag: bool,
           uba: Optional[dict] = None) -> dict[str, Any]:
    factors: list[dict[str, Any]] = []

    def add(name: str, pts: int, evidence: str) -> None:
        factors.append({"factor": name, "points": pts, "evidence": evidence})

    model_flag = score >= threshold
    if model_flag:
        add("model_score", 2, f"Isolation Forest anomaly score {score:.3f} is at or above the threshold "
                              f"{threshold:.3f} (a relative ranking, not a probability).")
        if score - threshold >= 0.05:
            add("score_margin", 1, f"The score exceeds the threshold by {score - threshold:.3f}.")

    fa, ips = int(data["failed_attempts"]), int(data["unique_ips_24h"])
    nd, cc, hr = int(data["new_device"]), int(data["country_changed"]), int(data["login_hour"])

    if rule_flag:
        parts = []
        if fa >= 8:
            parts.append(f"failed_attempts={fa} (>= 8)")
        if nd == 1 and cc == 1:
            parts.append("new_device=1 and country_changed=1")
        add("rule_baseline", 1, "Rule baseline triggered: " + "; ".join(parts) + ".")
    if fa >= 8:
        add("failed_attempts", 2, f"failed_attempts={fa} in the observation window (>= 8).")
    elif fa >= 5:
        add("failed_attempts", 1, f"failed_attempts={fa} in the observation window (5-7).")
    if ips >= 4:
        add("unique_ips_24h", 1, f"unique_ips_24h={ips} distinct source IPs in 24 hours (>= 4).")
    if nd == 1 and cc == 1:
        add("device_location", 2, "new_device=1 and country_changed=1 on the same event.")
    elif nd == 1 or cc == 1:
        add("device_location", 1, "new_device=1." if nd == 1 else "country_changed=1.")
    if hr <= 5:
        add("early_hours", 1, f"login_hour={hr} (between 00:00 and 05:59).")

    limitations: list[str] = []
    if uba and uba.get("status") == "ok" and uba["count"] > 0:
        add("user_baseline", 2 if uba["count"] >= 2 else 1,
            "Differs from this user's own earlier history: " + "; ".join(d["detail"] for d in uba["deviations"]) + ".")
    elif uba and uba.get("status") == "insufficient_history":
        limitations.append(f"No user baseline: only {uba['n_prior']} earlier events for this user "
                           f"(minimum required is set per scan).")
    elif uba and uba.get("status") in ("unavailable", "no_user"):
        limitations.append("No user baseline: the file has no usable username for this event.")

    points = sum(f["points"] for f in factors)
    flagged = model_flag or rule_flag
    severity = band(points) if flagged else "none"

    context = {k: data[k] for k in CONTEXT_FIELDS if data.get(k) not in (None, "")}
    detectors = [n for n, on in (("Isolation Forest", model_flag), ("rule baseline", rule_flag)) if on]
    if flagged:
        summary = (f"{severity.upper()} triage priority ({points} points). Flagged by "
                   f"{' and '.join(detectors)}. " + ("Signals: " + ", ".join(f["factor"] for f in factors) + ". " if factors else "")
                   + "This is a lead for a human analyst, not proof of an attack.")
    else:
        summary = "Not flagged by either detector at the current threshold; shown for context only."
    if model_flag != rule_flag and flagged:
        limitations.append("The detectors disagree (only one flagged this event); treat the signal with extra care.")

    steps = _steps(fa, ips, nd, cc, hr, context, uba)
    return {
        "severity": severity, "points": points, "factors": factors, "context": context,
        "summary": summary, "steps": steps,
        "benign_possibilities": [
            "Travel, a new or replaced device, a VPN, or shift work can all look anomalous.",
            "A shared or service account, a mistyped password, or a recent password reset.",
        ],
        "limitations": limitations + [
            "Anomaly scores are relative rankings, not calibrated probabilities.",
            "Evidence is limited to the columns in the uploaded file.",
        ],
    }


def _steps(fa: int, ips: int, nd: int, cc: int, hr: int, ctx: dict, uba: Optional[dict]) -> list[str]:
    who = f"user {ctx['username']}" if "username" in ctx else "this account"
    when = f" around {ctx['timestamp']}" if "timestamp" in ctx else ""
    steps = [f"Pull the raw authentication log entries for {who}{when} and confirm they match this record."]
    if fa >= 5:
        steps.append("Check whether the failed attempts targeted one account or many, and whether lockout/MFA "
                     "controls triggered. Any lockout or password reset must be decided by an authorised analyst.")
    if ips >= 4:
        steps.append(f"Review the {ips} source IPs against your approved asset inventory and threat-intelligence "
                     "sources; an unfamiliar IP is not by itself malicious.")
    if nd == 1 or cc == 1:
        steps.append("Verify with the account owner through an independent, trusted channel whether they used a "
                     "new device or location (for example, travel).")
    if hr <= 5:
        steps.append("Check whether the user's working pattern or time zone explains an early-hours login.")
    if uba and uba.get("status") == "ok" and uba["count"] > 0:
        steps.append("Compare with this user's profile in the Users tab to see what is normal for them.")
    steps.append("Record the outcome with the alert status and a note. Escalate under your incident process; "
                 "this tool performs no automatic remediation.")
    return steps
