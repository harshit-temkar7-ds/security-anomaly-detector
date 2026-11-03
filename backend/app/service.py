"""Orchestration between validation, scoring, UBA, persistence and the API layer."""
from __future__ import annotations

import json
import uuid
from collections import Counter
from typing import Any, Optional

import numpy as np
import pandas as pd

from . import store, triage
from .config import FEATURES, LABEL_COLUMN, STATUSES, settings
from .evaluation import agreement, compute_metrics, flag_rate_suggestions, threshold_sweep
from .investigation import SEVERITY_ORDER, assess
from .model import score
from .rules import review_reasons, rule_flags
from .uba import compute_uba, user_profile
from .validation import extract_labels, validate_features

WARNING = (
    "Anomaly flags are not proof of an attack. Scores are not calibrated probabilities. "
    "Review reasons are simple rules, not explanations of the model. "
    "Not production-ready (no authentication, no rate limiting)."
)
EVAL_NOTE = ("Labels are user-provided. Metrics describe this file only and do not prove "
             "real-world effectiveness.")


# ------------------------------------------------------------- summaries
def summarise(scores: np.ndarray, rules: np.ndarray, labels: Optional[np.ndarray],
              hours: np.ndarray, threshold: float) -> tuple[np.ndarray, Optional[dict], list[dict]]:
    flags = scores >= threshold
    evaluation = None
    if labels is not None:
        evaluation = {"positives": int(labels.sum()),
                      "model": compute_metrics(labels, flags, scores),
                      "rules": compute_metrics(labels, rules), "note": EVAL_NOTE}
    hourly = (pd.DataFrame({"hour": hours, "flagged": flags})
              .groupby("hour")["flagged"].agg(total="size", flagged="sum")
              .reindex(range(24), fill_value=0).reset_index().astype(int).to_dict(orient="records"))
    return flags, evaluation, hourly


# --------------------------------------------------------------- analyse
def analyze_dataframe(df: pd.DataFrame, filename: str, mode: str,
                      threshold: Optional[float], uba_min_history: int) -> str:
    X = validate_features(df)
    y = extract_labels(df)
    scores, _, model_thr, version = score(X, mode)
    active = float(threshold) if threshold is not None else float(model_thr)
    rules = rule_flags(X).to_numpy()
    flags, evaluation, hourly = summarise(scores, rules, y, X["login_hour"].to_numpy(), active)

    # Features used for UBA come from validated ints; username/timestamp are passthrough columns.
    uba_frame = X.copy()
    for col in ("username", "timestamp"):
        if col in df.columns:
            uba_frame[col] = df[col].to_numpy()
    uba, basis = compute_uba(uba_frame, uba_min_history)

    merged = df.copy()
    merged[FEATURES] = X
    records = json.loads(merged.to_json(orient="records", date_format="iso"))
    reasons = review_reasons(X).tolist()
    scan_id = uuid.uuid4().hex[:12]

    events = []
    for i, rec in enumerate(records):
        user = rec.get("username")
        events.append({
            "scan_id": scan_id, "row": i + 1, "data_json": json.dumps(rec),
            "score": round(float(scores[i]), 6), "rule_flag": int(rules[i]),
            "label": int(y[i]) if y is not None else None, "hour": int(X["login_hour"].iloc[i]),
            "username": str(user).strip() if user not in (None, "") else None,
            "review_reason": reasons[i], "uba_json": json.dumps(uba[i]),
        })
    store.save_scan({
        "scan_id": scan_id, "created_at": store.now(), "filename": filename[:255], "mode": mode,
        "model_version": version, "model_threshold": round(float(model_thr), 6),
        "threshold": round(active, 6), "rows_analyzed": len(df), "anomalies_flagged": int(flags.sum()),
        "rule_flags": int(rules.sum()), "has_labels": y is not None, "uba_min_history": uba_min_history,
        "uba_basis": basis, "evaluation": evaluation, "hourly": hourly, "warning": WARNING,
    }, events)
    return scan_id


def _assess(ev: dict, thr: float) -> dict:
    return assess(ev["data"], ev["score"], thr, ev["rule_flag"], ev["uba"])


def scan_response(scan_id: str) -> Optional[dict[str, Any]]:
    scan = store.get_scan(scan_id)
    if scan is None:
        return None
    thr = scan["threshold"]
    results, sev_counts = [], Counter()
    for ev in store.load_events(scan_id):
        a = _assess(ev, thr) if (ev["score"] >= thr or ev["rule_flag"]) else {"severity": "none"}
        if ev["score"] >= thr:
            sev_counts[a["severity"]] += 1
        results.append({
            **ev["data"], "row": ev["row"], "is_anomaly": ev["score"] >= thr,
            "anomaly_score": ev["score"], "rule_flag": ev["rule_flag"],
            "review_reason": ev["review_reason"], "severity": a["severity"], "status": ev["status"],
            "uba_status": ev["uba"]["status"], "uba_deviations": ev["uba"]["count"],
        })
    return {
        **{k: scan[k] for k in ("scan_id", "created_at", "filename", "mode", "model_version", "threshold",
                                "rows_analyzed", "anomalies_flagged", "rule_flags", "hourly",
                                "evaluation", "warning", "model_threshold", "has_labels",
                                "uba_basis", "uba_min_history")},
        "anomaly_rate": round(scan["anomalies_flagged"] / scan["rows_analyzed"], 4),
        "severity_counts": {k: sev_counts.get(k, 0) for k in SEVERITY_ORDER[1:]},
        "results": results,
    }


# ------------------------------------------------------------ thresholds
def _arrays(scan_id: str) -> dict[str, np.ndarray]:
    a = store.score_arrays(scan_id)
    return {"row": np.array(a["row"]), "score": np.array(a["score"], dtype=float),
            "rules": np.array(a["rule_flag"], dtype=bool), "hour": np.array(a["hour"]),
            "label": None if any(v is None for v in a["label"]) else np.array(a["label"], dtype=int)}


def threshold_evaluation(scan: dict, threshold: float) -> dict[str, Any]:
    a = _arrays(scan["scan_id"])
    flags, evaluation, _ = summarise(a["score"], a["rules"], a["label"], a["hour"], threshold)
    return {
        "scan_id": scan["scan_id"], "threshold": threshold, "active_threshold": scan["threshold"],
        "model_threshold": scan["model_threshold"], "score_min": round(float(a["score"].min()), 5),
        "score_max": round(float(a["score"].max()), 5), "flagged": int(flags.sum()),
        "flag_rate": round(float(flags.mean()), 4), "rule_flags": int(a["rules"].sum()),
        "evaluation": evaluation, "agreement": agreement(flags, a["rules"]),
        "sweep": threshold_sweep(a["score"], a["label"], a["rules"]),
        "suggestions": flag_rate_suggestions(a["score"]),
        "note": ("Threshold choices are label-free (flag-rate quantiles of this scan or the model default). "
                 "Labels, if present, are used only to report metrics, never to pick or fit the threshold. "
                 "Choosing the 'best' point on the same labels and reporting it would overstate performance."),
    }


def apply_threshold(scan: dict, threshold: float) -> None:
    a = _arrays(scan["scan_id"])
    flags, evaluation, hourly = summarise(a["score"], a["rules"], a["label"], a["hour"], threshold)
    store.update_scan_summary(scan["scan_id"], round(threshold, 6), int(flags.sum()), evaluation, hourly)


# ---------------------------------------------------------------- alerts
def alert_summary(ev: dict, thr: float) -> dict[str, Any]:
    a = _assess(ev, thr)
    return {
        "row": ev["row"], "anomaly_score": ev["score"], "flagged_by_model": ev["score"] >= thr,
        "rule_flag": ev["rule_flag"], "severity": a["severity"], "points": a["points"],
        "status": ev["status"], "username": ev["username"], "review_reason": ev["review_reason"],
        "uba_status": ev["uba"]["status"], "uba_deviations": ev["uba"]["count"], "data": ev["data"],
    }


def list_alerts(scan: dict, detector: str, severity: Optional[str], status: Optional[str],
                username: Optional[str], q: Optional[str], page: int, page_size: int,
                threshold: Optional[float] = None) -> dict[str, Any]:
    thr = scan["threshold"] if threshold is None else threshold
    where = {"model": "AND score >= ?", "rules": "AND rule_flag = 1",
             "either": "AND (score >= ? OR rule_flag = 1)"}[detector]
    args: tuple = (thr,) if detector != "rules" else ()
    if status:
        where += " AND status = ?"; args += (status,)
    if username:
        where += " AND username = ?"; args += (username,)
    items = [alert_summary(e, thr) for e in store.load_events(scan["scan_id"], where, args)]
    if q:
        ql = q.lower()
        items = [i for i in items if ql in json.dumps(i["data"]).lower() or ql in i["review_reason"].lower()]
    sev_counts = Counter(i["severity"] for i in items)
    if severity:
        items = [i for i in items if i["severity"] == severity]
    items.sort(key=lambda i: (-SEVERITY_ORDER.index(i["severity"]), -i["points"], -i["anomaly_score"], i["row"]))
    start = (page - 1) * page_size
    shown = triage.annotate(items[start:start + page_size])  # learned priority for this page only
    return {"items": shown, "total": len(items), "page": page, "page_size": page_size,
            "severity_counts": {k: sev_counts.get(k, 0) for k in SEVERITY_ORDER},
            "status_counts": store.status_counts(scan["scan_id"], thr)}


def alert_detail(scan: dict, ev: dict) -> dict[str, Any]:
    a = _assess(ev, scan["threshold"])
    base = alert_summary(ev, scan["threshold"])
    triage.annotate([base])
    return {**base, "threshold": scan["threshold"], "summary": a["summary"],
            "factors": a["factors"], "context": a["context"], "steps": a["steps"],
            "benign_possibilities": a["benign_possibilities"], "limitations": a["limitations"],
            "uba": ev["uba"], "notes": store.list_notes(scan["scan_id"], ev["row"]),
            "status_updated_at": ev["status_updated_at"]}


# ----------------------------------------------------------------- users
def list_users(scan: dict, q: Optional[str], page: int, page_size: int) -> dict[str, Any]:
    thr = scan["threshold"]
    users: dict[str, dict] = {}
    for ev in store.load_events(scan["scan_id"], "AND username IS NOT NULL"):
        u = users.setdefault(ev["username"], {"username": ev["username"], "events": 0, "flagged": 0,
                                              "max_score": 0.0, "deviation_events": 0})
        u["events"] += 1
        u["flagged"] += ev["score"] >= thr
        u["max_score"] = max(u["max_score"], ev["score"])
        u["deviation_events"] += ev["uba"]["count"] > 0
    items = sorted(users.values(), key=lambda u: (-u["flagged"], -u["max_score"], u["username"]))
    if q:
        items = [u for u in items if q.lower() in u["username"].lower()]
    start = (page - 1) * page_size
    return {"items": items[start:start + page_size], "total": len(items), "page": page,
            "page_size": page_size, "uba_basis": scan["uba_basis"], "min_history": scan["uba_min_history"]}


def get_user_profile(scan: dict, username: str) -> Optional[dict[str, Any]]:
    events = store.load_events(scan["scan_id"], "AND username = ?", (username,))
    if not events:
        return None
    prof = user_profile(events, scan["uba_min_history"])
    notice = None
    if not prof["sufficient_history"]:
        notice = (f"Insufficient history: {prof['events']} events (needs more than {scan['uba_min_history']}). "
                  "Deviations are not claimed for this user.")
    elif scan["uba_basis"] == "row_order":
        notice = "No usable timestamps: the file order is assumed to be chronological."
    dev = [{"row": e["row"], "anomaly_score": e["score"], "n_prior": e["uba"]["n_prior"],
            "deviations": e["uba"]["deviations"]} for e in events if e["uba"]["count"] > 0]
    dev.sort(key=lambda d: -len(d["deviations"]))
    return {"username": username, "profile": prof, "min_history": scan["uba_min_history"],
            "uba_basis": scan["uba_basis"], "notice": notice, "deviation_events": dev[:50]}


# --------------------------------------------------------------- reports
def report_context(scan: dict, top: int, include_notes: bool, row: Optional[int] = None) -> dict[str, Any]:
    thr = scan["threshold"]
    a = _arrays(scan["scan_id"])
    flags = a["score"] >= thr
    selected = (store.load_events(scan["scan_id"], "AND row = ?", (row,)) if row
                else store.load_events(scan["scan_id"], "AND (score >= ? OR rule_flag = 1)", (thr,)))
    ranked = sorted(((_assess(e, thr), e) for e in selected),
                    key=lambda p: (-p[0]["points"], -p[1]["score"], p[1]["row"]))
    sev_counts = Counter(x[0]["severity"] for x in ranked if x[1]["score"] >= thr)
    alerts = [{
        "row": e["row"], "severity": x["severity"], "points": x["points"], "score": e["score"],
        "status": e["status"], "context": x["context"], "factors": x["factors"], "steps": x["steps"],
        "limitations_event": [l for l in x["limitations"] if not l.startswith(("Anomaly scores", "Evidence is"))],
        "notes": store.list_notes(scan["scan_id"], e["row"]) if include_notes else [],
    } for x, e in ranked[:top]]

    st = store.status_counts(scan["scan_id"], thr)
    users_unknown = sum(1 for e in store.load_events(scan["scan_id"], "AND (score >= ?)", (thr,))
                        if e["uba"]["status"] != "ok")
    unc = [
        "Anomaly scores are relative rankings from an unsupervised model, not calibrated probabilities; "
        "an anomaly is not necessarily malicious and a normal-looking attack may not be flagged.",
        f"Results depend on the threshold ({thr:.4f}). A different threshold changes which events are flagged "
        f"({int(flags.sum())} flagged now).",
    ]
    if scan["has_labels"]:
        unc.append("Metrics use labels supplied in the file, so they describe this file only, "
                   "not real-world performance.")
    else:
        unc.append("No labels were provided, so detection quality (precision/recall) is unknown.")
    if scan["mode"] == "batch":
        unc.append("Batch mode fitted the model on this file, so scores are relative to this file only.")
    if users_unknown:
        unc.append(f"{users_unknown} flagged events have no usable user baseline (insufficient history or no "
                   "username), so no user-level conclusion is made for them.")
    if scan["uba_basis"] == "row_order":
        unc.append("User baselines assume the file is in chronological order because timestamps were unusable.")
    if len(ranked) > top:
        unc.append(f"Only the top {top} of {len(ranked)} alerts are detailed in this report.")

    c = Counter()
    for x, e in ranked:
        for f in x["factors"]:
            c[f["factor"]] += 1
    actions = []
    hi = sev_counts.get("critical", 0) + sev_counts.get("high", 0)
    if hi:
        actions.append(f"An analyst should review the {hi} high/critical alerts first and record outcomes in the tool.")
    if c["failed_attempts"]:
        actions.append(f"For the {c['failed_attempts']} alerts with many failed attempts, an authorised person may "
                       "decide whether account lockout, MFA enforcement or password reset is warranted.")
    if c["device_location"]:
        actions.append(f"Verify {c['device_location']} new-device/location alerts with the account owners through "
                       "an independent channel before taking any action.")
    actions.append("Treat dismissals as feedback: mark false positives so thresholds and rules can be tuned by people.")
    actions.append("This report recommends no automatic remediation. Any blocking or account change requires "
                   "human approval under your incident process.")
    return {"scan": scan, "evaluation": scan["evaluation"], "severity_counts": dict(sev_counts),
            "status_counts": st, "agreement": agreement(flags, a["rules"]), "alerts": alerts,
            "uncertainty": unc, "actions": actions}
