"""Learning from analyst feedback: a transparent second-stage triage model.

Stage 1 (Isolation Forest) is unsupervised and cannot know what *your* analysts consider
benign. Stage 2 learns that from their decisions:

    status = false_positive  -> benign      (0)
    status = escalated       -> suspicious  (1)
    anything else            -> ignored (e.g. "resolved" does not say which way it went)

It is a standardised logistic regression on the five event features plus the Isolation Forest
score, so its weights can be shown to a human. It only ADDS a "learned priority" (the estimated
chance that an analyst would escalate the alert). It never closes, hides or blocks anything.

Safety rails: out-of-fold cross-validation is reported, activation is refused unless the model
clears a quality gate, every activation keeps the previous version for one-click rollback, and
feedback comes from a biased sample (alerts analysts chose to review), which is stated in the UI.
"""
from __future__ import annotations

import logging
import shutil
from datetime import datetime, timezone
from functools import lru_cache
from threading import Lock
from typing import Any, Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from . import store
from .config import FEATURES, settings

log = logging.getLogger(__name__)

COLUMNS = FEATURES + ["anomaly_score"]
FEEDBACK_LABELS = {"false_positive": 0, "escalated": 1}
MIN_PER_CLASS = 8          # reviewed alerts needed in EACH class before training is allowed
MIN_CV_AUC = 0.75          # quality gate: out-of-fold ROC-AUC
MAX_MISSED_RATE = 0.05     # gate: share of escalated alerts the model would rank as "likely benign"
BENIGN_CUTOFF = 0.20       # learned priority below this is labelled "likely benign" (a suggestion)
_lock = Lock()


# ------------------------------------------------------------------ data
def _frame(rows: list[dict[str, Any]]) -> pd.DataFrame:
    return pd.DataFrame(
        [{**{c: int(r["data"][c]) for c in FEATURES}, "anomaly_score": float(r["score"]),
          "y": FEEDBACK_LABELS[r["status"]]} for r in rows]
    )


def counts() -> dict[str, int]:
    totals = store.status_totals()
    return {"false_positive": totals.get("false_positive", 0), "escalated": totals.get("escalated", 0),
            "resolved": totals.get("resolved", 0), "in_review": totals.get("in_review", 0)}


# ------------------------------------------------------------- persistence
def _prev_path():
    return settings.triage_path.with_name(settings.triage_path.stem + ".prev.joblib")


@lru_cache(maxsize=1)
def _load() -> Optional[dict[str, Any]]:
    path = settings.triage_path
    if not path.exists():
        return None
    try:
        return joblib.load(path)
    except Exception as exc:  # stale/damaged file must never break alert listing
        log.warning("Could not load triage model (%s); ignoring it.", type(exc).__name__)
        return None


def active() -> Optional[dict[str, Any]]:
    return _load()


def _reset_cache() -> None:
    _load.cache_clear()


# ---------------------------------------------------------------- scoring
def annotate(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add `triage` (0-1 learned priority, or None) and `triage_label` to alert dicts, in place."""
    bundle = active()
    if bundle is None or not items:
        for it in items:
            it["triage"], it["triage_label"] = None, None
        return items
    X = pd.DataFrame([{**{c: int(i["data"][c]) for c in FEATURES}, "anomaly_score": float(i["anomaly_score"])}
                      for i in items])[COLUMNS]
    p = bundle["model"].predict_proba(X)[:, 1]
    for it, v in zip(items, p):
        it["triage"] = round(float(v), 3)
        it["triage_label"] = "likely benign" if v < BENIGN_CUTOFF else ("likely suspicious" if v >= 0.8 else "uncertain")
    return items


# --------------------------------------------------------------- training
def _fit(df: pd.DataFrame):
    pipe = make_pipeline(StandardScaler(), LogisticRegression(class_weight="balanced", max_iter=2000))
    return pipe.fit(df[COLUMNS], df["y"])


def _drivers(pipe) -> list[dict[str, Any]]:
    coefs = pipe[-1].coef_[0]
    out = [{"feature": c, "weight": round(float(w), 3),
            "direction": "toward escalate" if w > 0 else "toward benign"} for c, w in zip(COLUMNS, coefs)]
    return sorted(out, key=lambda d: -abs(d["weight"]))


def summary() -> dict[str, Any]:
    c = counts()
    b = active()
    need = {k: max(0, MIN_PER_CLASS - c[k]) for k in ("false_positive", "escalated")}
    return {
        "counts": c, "min_per_class": MIN_PER_CLASS, "still_needed": need,
        "can_train": all(v == 0 for v in need.values()),
        "active": None if b is None else {k: b[k] for k in ("version", "created_at", "trained_on", "cv", "drivers")},
        "has_previous": _prev_path().exists(),
        "gate": {"min_cv_auc": MIN_CV_AUC, "max_missed_escalation_rate": MAX_MISSED_RATE,
                 "benign_cutoff": BENIGN_CUTOFF},
        "caveat": ("Feedback only covers alerts your analysts chose to review, so it is a biased sample. "
                   "The learned priority is a ranking aid for humans; it never closes or hides alerts."),
    }


def train(activate: bool = False) -> dict[str, Any]:
    rows = store.feedback_events()
    df = _frame(rows) if rows else pd.DataFrame(columns=COLUMNS + ["y"])
    n_ben, n_sus = int((df["y"] == 0).sum()), int((df["y"] == 1).sum())
    if min(n_ben, n_sus) < MIN_PER_CLASS:
        return {"status": "insufficient_feedback", "activated": False,
                "counts": {"false_positive": n_ben, "escalated": n_sus}, "min_per_class": MIN_PER_CLASS,
                "message": (f"Need at least {MIN_PER_CLASS} false-positive and {MIN_PER_CLASS} escalated alerts "
                            f"(have {n_ben} and {n_sus}). Review more alerts in the Alerts tab first.")}

    folds = min(5, n_ben, n_sus)
    pipe = make_pipeline(StandardScaler(), LogisticRegression(class_weight="balanced", max_iter=2000))
    oof = cross_val_predict(pipe, df[COLUMNS], df["y"], method="predict_proba",
                            cv=StratifiedKFold(folds, shuffle=True, random_state=0))[:, 1]
    y = df["y"].to_numpy()
    auc = float(roc_auc_score(y, oof))
    score_auc = float(roc_auc_score(y, df["anomaly_score"]))
    missed = float(((oof < BENIGN_CUTOFF) & (y == 1)).sum() / max(1, n_sus))
    removed = float(((oof < BENIGN_CUTOFF) & (y == 0)).sum() / max(1, n_ben))
    cv = {"folds": folds, "roc_auc": round(auc, 3), "isolation_forest_score_alone_auc": round(score_auc, 3),
          "benign_ranked_low": round(removed, 3), "escalated_ranked_low": round(missed, 3),
          "cutoff": BENIGN_CUTOFF}

    reasons = []
    if auc < MIN_CV_AUC:
        reasons.append(f"cross-validated AUC {auc:.2f} is below the {MIN_CV_AUC:.2f} gate")
    if missed > MAX_MISSED_RATE:
        reasons.append(f"it would rank {missed:.0%} of escalated alerts as likely benign "
                       f"(limit {MAX_MISSED_RATE:.0%})")
    passed = not reasons

    result: dict[str, Any] = {
        "status": "ok", "cv": cv, "passed_gate": passed, "blocked_reasons": reasons,
        "counts": {"false_positive": n_ben, "escalated": n_sus}, "activated": False,
        "note": ("Cross-validation is out-of-fold: each reviewed alert is scored by a model that did not "
                 "see it. Results reflect only the alerts reviewed in this scan, not real-world performance."),
    }
    if activate:
        if not passed:
            result["message"] = "Not activated: " + "; ".join(reasons) + "."
            return result
        final = _fit(df)
        bundle = {"model": final, "features": COLUMNS, "cv": cv, "drivers": _drivers(final),
                  "version": datetime.now(timezone.utc).strftime("tri-%Y%m%d%H%M%S"),
                  "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  "trained_on": {"false_positive": n_ben, "escalated": n_sus}}
        with _lock:
            settings.triage_path.parent.mkdir(parents=True, exist_ok=True)
            if settings.triage_path.exists():
                shutil.copyfile(settings.triage_path, _prev_path())
            joblib.dump(bundle, settings.triage_path)
            _reset_cache()
        result.update(activated=True, version=bundle["version"], drivers=bundle["drivers"],
                      message="Activated. New alerts listings now show a learned priority.")
    else:
        result["drivers"] = _drivers(_fit(df))
        result["message"] = ("Preview only. " + ("It clears the quality gate and can be activated."
                             if passed else "It does not clear the quality gate yet."))
    return result


def rollback() -> dict[str, Any]:
    """Restore the previous triage model, or switch triage off if there was none."""
    with _lock:
        prev = _prev_path()
        if prev.exists():
            shutil.copyfile(prev, settings.triage_path)
            prev.unlink()
            _reset_cache()
            return {"status": "restored_previous", "active_version": (active() or {}).get("version")}
        if settings.triage_path.exists():
            settings.triage_path.unlink()
            _reset_cache()
            return {"status": "disabled", "active_version": None}
    return {"status": "nothing_to_roll_back", "active_version": None}
