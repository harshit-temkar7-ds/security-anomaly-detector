"""User Behavior Analytics: per-user baselines built ONLY from each user's earlier events.

No future leakage: an event is compared with the events that sort strictly before it
for the same user, ordered by (timestamp, file position) - or by file position alone when
timestamps are missing/unparseable (basis = "row_order"; the file is then assumed to be
chronological). Appending later events never changes an earlier event's result.

A user needs at least `min_history` prior events; otherwise the status is
"insufficient_history" and NO deviation is claimed.
"""
from __future__ import annotations

import warnings

import numpy as np
import pandas as pd

from .config import FEATURES

Z_THRESHOLD = 3.0       # |z| for count features (std floored at 1.0 to avoid tiny-variance noise)
HOUR_WINDOW = 2         # "similar hour" = within +/- 2 hours (circular)
HOUR_SHARE_MAX = 0.05   # deviation if <5% of prior logins were at a similar hour
RATE_MAX = 0.10         # deviation if event has new device/country but prior rate <= 10%


def _blank(status: str, n_prior: int = 0) -> dict:
    return {"status": status, "n_prior": int(n_prior), "deviations": [], "count": 0}


def compute_uba(frame: pd.DataFrame, min_history: int = 10) -> tuple[list[dict], str]:
    """`frame` holds validated integer FEATURES plus optional username/timestamp columns.
    Returns (one result dict per input row, in input order; basis string)."""
    n = len(frame)
    if "username" not in frame.columns:
        return [_blank("unavailable") for _ in range(n)], "none"

    user = frame["username"].astype("object")
    valid = (user.notna() & user.astype(str).str.strip().ne("")).to_numpy()

    basis, t = "row_order", np.zeros(n, dtype="int64")
    if "timestamp" in frame.columns:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")  # "could not infer format" noise on unparseable input
                parsed = pd.to_datetime(frame["timestamp"], errors="coerce", utc=True)
            if parsed.notna().all():
                basis, t = "timestamp", parsed.astype("int64").to_numpy()
        except (ValueError, TypeError):
            pass

    s = pd.DataFrame({"user": user.astype(str).str.strip().to_numpy(), "t": t, "pos": np.arange(n)})
    for c in FEATURES:
        s[c] = frame[c].to_numpy(dtype=float)
    s = s[valid].sort_values(["user", "t", "pos"], kind="stable").reset_index(drop=True)

    out = [_blank("no_user") for _ in range(n)]
    if s.empty:
        return out, basis

    grp = s["user"]
    n_prior = s.groupby("user", sort=False).cumcount().to_numpy()
    denom = np.maximum(n_prior, 1)

    def prior_mean_std(col: str) -> tuple[np.ndarray, np.ndarray]:
        v = s[col]
        csum = (v.groupby(grp, sort=False).cumsum() - v).to_numpy()
        csq = ((v ** 2).groupby(grp, sort=False).cumsum() - v ** 2).to_numpy()
        mean = csum / denom
        return mean, np.sqrt(np.clip(csq / denom - mean ** 2, 0, None))

    stats = {c: prior_mean_std(c) for c in ("failed_attempts", "unique_ips_24h", "new_device", "country_changed")}

    hours = s["login_hour"].to_numpy().astype(int)
    onehot = np.zeros((len(s), 24))
    onehot[np.arange(len(s)), hours] = 1.0
    prior_hist = pd.DataFrame(onehot).groupby(grp.to_numpy(), sort=False).cumsum().to_numpy() - onehot
    near = sum(prior_hist[np.arange(len(s)), (hours + d) % 24] for d in range(-HOUR_WINDOW, HOUR_WINDOW + 1))
    hour_share = near / denom

    cols = {c: s[c].to_numpy() for c in FEATURES}
    pos = s["pos"].to_numpy()
    for i in range(len(s)):
        k = int(n_prior[i])
        if k < min_history:
            out[pos[i]] = _blank("insufficient_history", k)
            continue
        devs: list[dict] = []
        for col in ("failed_attempts", "unique_ips_24h"):
            mean, std = stats[col][0][i], stats[col][1][i]
            z = (cols[col][i] - mean) / max(std, 1.0)
            if z >= Z_THRESHOLD:
                devs.append({
                    "feature": col, "value": int(cols[col][i]),
                    "detail": f"{col}={int(cols[col][i])} vs this user's prior mean {mean:.1f} "
                              f"(std {std:.1f}, n={k}); z={z:.1f}",
                })
        if hour_share[i] < HOUR_SHARE_MAX:
            devs.append({
                "feature": "login_hour", "value": int(hours[i]),
                "detail": f"login_hour={hours[i]}: only {hour_share[i]:.1%} of this user's {k} prior "
                          f"logins were within {HOUR_WINDOW}h of this hour",
            })
        for col, label in (("new_device", "a new device"), ("country_changed", "a changed country")):
            rate = stats[col][0][i]
            if cols[col][i] == 1 and rate <= RATE_MAX:
                devs.append({
                    "feature": col, "value": 1,
                    "detail": f"{col}=1 but only {rate:.1%} of this user's {k} prior logins involved {label}",
                })
        out[pos[i]] = {"status": "ok", "n_prior": k, "deviations": devs, "count": len(devs)}
    return out, basis


def user_profile(events: list[dict], min_history: int) -> dict:
    """Descriptive profile of one user over the WHOLE scan (a summary for analysts).
    Per-event deviations (above) never use this; they only use earlier events."""
    d = [e["data"] for e in events]
    n = len(d)
    hist = [0] * 24
    for x in d:
        hist[int(x["login_hour"])] += 1

    def mean(k: str) -> float:
        return round(float(np.mean([x[k] for x in d])), 3) if d else 0.0

    ts = pd.to_datetime([x.get("timestamp") for x in d if x.get("timestamp")], errors="coerce", utc=True)
    ts = ts.dropna()
    return {
        "events": n,
        "sufficient_history": n > min_history,
        "hour_histogram": hist,
        "mean_failed_attempts": mean("failed_attempts"),
        "max_failed_attempts": max((x["failed_attempts"] for x in d), default=0),
        "mean_unique_ips_24h": mean("unique_ips_24h"),
        "new_device_rate": mean("new_device"),
        "country_changed_rate": mean("country_changed"),
        "first_seen": ts.min().isoformat() if not ts.empty else None,
        "last_seen": ts.max().isoformat() if not ts.empty else None,
    }
