"""Transparent rule baseline + human-readable review reasons.

The reasons are simple rule checks, NOT a causal explanation of the Isolation
Forest decision. They give the analyst starting points for investigation.
"""
from __future__ import annotations

import pandas as pd


def rule_flags(df: pd.DataFrame) -> pd.Series:
    """Baseline detector: many failures, or new device AND new country."""
    return (df["failed_attempts"] >= 8) | ((df["new_device"] == 1) & (df["country_changed"] == 1))


def review_reasons(df: pd.DataFrame) -> pd.Series:
    checks = [
        (df["failed_attempts"] >= 5, "many failed attempts"),
        (df["unique_ips_24h"] >= 4, "many source IPs"),
        (df["new_device"] == 1, "new device"),
        (df["country_changed"] == 1, "location changed"),
        (df["login_hour"] <= 5, "login during early hours"),
    ]
    reasons = pd.Series([[] for _ in range(len(df))], index=df.index, dtype=object)
    for mask, text in checks:
        for idx in df.index[mask.to_numpy()]:
            reasons.at[idx] = reasons.at[idx] + [text]
    return reasons.map(lambda r: ", ".join(r) if r else "no configured rule triggered")
