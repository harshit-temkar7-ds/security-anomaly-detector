"""Synthetic login-event generator. All data is fictional.

IPs come from documentation-reserved ranges (RFC 5737) so they never map to real hosts.
Normal behaviour and three simulated attack patterns are generated; the patterns
deliberately overlap with normal behaviour so the detector is NOT perfect.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .config import RANDOM_SEED

ATTACK_TYPES = ["brute_force", "account_takeover", "credential_stuffing"]
ATTACK_PROBS = [0.40, 0.40, 0.20]
_IP_PREFIXES = ["203.0.113", "198.51.100", "192.0.2"]


def _bern(rng: np.random.Generator, p: float, n: int) -> np.ndarray:
    return (rng.random(n) < p).astype(int)


def _normal_events(rng: np.random.Generator, n: int) -> pd.DataFrame:
    working = np.clip(np.round(rng.normal(13, 3.5, n)), 6, 22)
    anytime = rng.integers(0, 24, n)
    hour = np.where(rng.random(n) < 0.92, working, anytime).astype(int)
    return pd.DataFrame(
        {
            "failed_attempts": np.minimum(rng.poisson(0.5, n), 6),
            "login_hour": hour,
            "unique_ips_24h": 1 + rng.poisson(0.3, n),
            "new_device": _bern(rng, 0.06, n),
            "country_changed": _bern(rng, 0.03, n),
            "label": 0,
            "attack_type": "none",
        }
    )


def _attack_events(rng: np.random.Generator, n: int) -> pd.DataFrame:
    kinds = rng.choice(ATTACK_TYPES, size=n, p=ATTACK_PROBS)
    df = pd.DataFrame(
        {
            "failed_attempts": 0,
            "login_hour": rng.integers(0, 24, n),
            "unique_ips_24h": 1,
            "new_device": 0,
            "country_changed": 0,
            "label": 1,
            "attack_type": kinds,
        }
    )
    m = kinds == "brute_force"
    k = int(m.sum())
    df.loc[m, "failed_attempts"] = rng.integers(6, 31, k)
    df.loc[m, "unique_ips_24h"] = 1 + rng.poisson(1.5, k)
    df.loc[m, "new_device"] = _bern(rng, 0.3, k)
    df.loc[m, "country_changed"] = _bern(rng, 0.2, k)

    m = kinds == "account_takeover"
    k = int(m.sum())
    df.loc[m, "failed_attempts"] = rng.poisson(1.5, k)
    df.loc[m, "unique_ips_24h"] = 2 + rng.poisson(1.5, k)
    df.loc[m, "new_device"] = _bern(rng, 0.9, k)
    df.loc[m, "country_changed"] = _bern(rng, 0.8, k)
    night = rng.integers(0, 6, k)
    df.loc[m, "login_hour"] = np.where(rng.random(k) < 0.7, night, df.loc[m, "login_hour"])

    m = kinds == "credential_stuffing"
    k = int(m.sum())
    df.loc[m, "failed_attempts"] = rng.integers(3, 12, k)
    df.loc[m, "unique_ips_24h"] = rng.integers(4, 12, k)
    df.loc[m, "new_device"] = _bern(rng, 0.5, k)
    df.loc[m, "country_changed"] = _bern(rng, 0.5, k)
    return df


def generate_login_events(
    n: int = 5000, anomaly_rate: float = 0.04, seed: int = RANDOM_SEED
) -> pd.DataFrame:
    """Return `n` fictional login events with simulated ground-truth labels."""
    rng = np.random.default_rng(seed)
    n_attack = int(round(n * anomaly_rate))
    df = pd.concat(
        [_normal_events(rng, n - n_attack), _attack_events(rng, n_attack)],
        ignore_index=True,
    )
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)

    day = rng.integers(0, 14, len(df))
    minute = rng.integers(0, 60, len(df))
    ts = pd.Timestamp("2026-01-01") + pd.to_timedelta(day, unit="D")
    ts = ts + pd.to_timedelta(df["login_hour"].to_numpy(), unit="h")
    ts = ts + pd.to_timedelta(minute, unit="m")

    prefix = rng.choice(_IP_PREFIXES, len(df))
    last = rng.integers(1, 255, len(df))
    meta = pd.DataFrame(
        {
            "event_id": [f"evt_{i:06d}" for i in range(len(df))],
            "timestamp": ts,
            "username": [f"user_{u:03d}" for u in rng.integers(1, 151, len(df))],
            "source_ip": [f"{p}.{o}" for p, o in zip(prefix, last)],
        }
    )
    out = pd.concat([meta, df], axis=1)
    cols = ["event_id", "timestamp", "username", "source_ip", "failed_attempts",
            "login_hour", "unique_ips_24h", "new_device", "country_changed",
            "label", "attack_type"]
    return out[cols]
