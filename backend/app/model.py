"""Isolation Forest training, persistence and scoring.

Two inference modes:
  baseline - a versioned model trained once on a synthetic baseline (default).
             Scores are comparable across uploads.
  batch    - fit a fresh model on the uploaded file. Scores are only relative
             to that file (the original guide's demo behaviour).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from .config import FEATURES, RANDOM_SEED, settings
from .synthetic import generate_login_events

log = logging.getLogger(__name__)
EXPECTED_FLAG_RATE = 0.04  # share of events we are willing to send to analysts


def _fit(X: pd.DataFrame, seed: int) -> IsolationForest:
    return IsolationForest(n_estimators=200, contamination="auto", random_state=seed).fit(X)


def _scores(forest: IsolationForest, X: pd.DataFrame) -> np.ndarray:
    return -forest.score_samples(X)  # larger = more anomalous


def train_baseline(
    n: int = 20_000, seed: int = RANDOM_SEED, flag_rate: float = EXPECTED_FLAG_RATE
) -> dict[str, Any]:
    """Train on synthetic data using FEATURES only. Labels are never used."""
    train = generate_login_events(n=n, anomaly_rate=0.03, seed=seed + 1)
    X = train[FEATURES]
    forest = _fit(X, seed)
    threshold = float(np.quantile(_scores(forest, X), 1 - flag_rate))
    return {
        "model": forest,
        "threshold": threshold,
        "features": FEATURES,
        "version": datetime.now(timezone.utc).strftime("if-%Y%m%d%H%M%S"),
        "flag_rate": flag_rate,
        "train_rows": n,
        "seed": seed,
    }


def save_bundle(bundle: dict[str, Any]) -> None:
    settings.model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, settings.model_path)


@lru_cache(maxsize=1)
def get_bundle() -> dict[str, Any]:
    """Load the saved model, training (and saving) one if none exists.

    Only load model files you created yourself: joblib/pickle can execute code.
    """
    if settings.model_path.exists():
        try:
            return joblib.load(settings.model_path)
        except Exception as exc:
            # Joblib files are tied to Python and library versions. A stale or
            # damaged local bundle must not make every upload fail.
            log.warning("Could not load saved model (%s); retraining baseline.", type(exc).__name__)
    log.info("No saved model found - training a baseline model.")
    bundle = train_baseline()
    try:
        save_bundle(bundle)
    except OSError:
        log.warning("Could not persist model; using in-memory copy.")
    return bundle


def score(X: pd.DataFrame, mode: str = "baseline") -> tuple[np.ndarray, np.ndarray, float, str]:
    """Return (scores, flags, threshold, model_version)."""
    if mode == "batch":
        forest = _fit(X, RANDOM_SEED)
        s = _scores(forest, X)
        thr = float(np.quantile(s, 1 - EXPECTED_FLAG_RATE))
        return s, s >= thr, thr, "batch-fit"
    bundle = get_bundle()
    s = _scores(bundle["model"], X[bundle["features"]])
    return s, s >= bundle["threshold"], bundle["threshold"], bundle["version"]
