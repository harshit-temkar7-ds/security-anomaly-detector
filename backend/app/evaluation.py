"""Metrics against (simulated) ground-truth labels."""
from __future__ import annotations

import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, scores: np.ndarray | None = None) -> dict:
    y_true = np.asarray(y_true).astype(int)
    y_pred = np.asarray(y_pred).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    auc = None
    if scores is not None and len(np.unique(y_true)) == 2:
        auc = round(float(roc_auc_score(y_true, scores)), 4)
    return {
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "roc_auc": auc,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


# ---------------------------------------------------------------- thresholds
def threshold_sweep(scores: np.ndarray, y: np.ndarray | None, rules: np.ndarray, points: int = 40) -> list[dict]:
    """Model metrics across thresholds. With labels this is a *diagnostic view only*:
    picking the best point on the same labels and reporting it would leak the labels.
    The default threshold is label-free (see model.py / flag-rate suggestions)."""
    scores = np.asarray(scores, dtype=float)
    out = []
    for t in np.linspace(scores.min(), scores.max(), points):
        pred = scores >= t
        item: dict = {"threshold": round(float(t), 5), "flagged": int(pred.sum()),
                      "precision": None, "recall": None, "f1": None}
        if y is not None:
            tp = int((pred & (y == 1)).sum())
            fp = int((pred & (y == 0)).sum())
            fn = int((~pred & (y == 1)).sum())
            p = tp / (tp + fp) if tp + fp else 0.0
            r = tp / (tp + fn) if tp + fn else 0.0
            item.update(precision=round(p, 4), recall=round(r, 4),
                        f1=round(2 * p * r / (p + r), 4) if p + r else 0.0)
        out.append(item)
    return out


def agreement(model_flags: np.ndarray, rules: np.ndarray) -> dict:
    m, r = np.asarray(model_flags, bool), np.asarray(rules, bool)
    return {"both": int((m & r).sum()), "model_only": int((m & ~r).sum()),
            "rules_only": int((~m & r).sum()), "neither": int((~m & ~r).sum())}


def flag_rate_suggestions(scores: np.ndarray) -> list[dict]:
    """Label-free threshold choices: 'flag the top X% of this scan's scores'."""
    return [{"flag_rate": q, "threshold": round(float(np.quantile(scores, 1 - q)), 5)}
            for q in (0.01, 0.02, 0.05, 0.10)]
