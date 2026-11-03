"""Turn the RBA (Risk-Based Authentication) login dataset into a CSV this dashboard can analyse.

Dataset: Wiefling, Jorgensen, Thunem, Lo Iacono, "Login Data Set for Risk-Based Authentication",
Zenodo, DOI 10.5281/zenodo.6782155. It is derived from real login behaviour at a large online
service, but IPs, user agents, timestamps and RTTs were generated for privacy. Say so when you
present results, and cite the authors.

Usage (from backend/):
    python -m scripts.import_rba "C:\\path\\to\\rba-dataset.csv" --out ..\\data\\rba_sample.csv

How it works (the file is ~8 GB, so it is streamed in chunks and never loaded whole):
  pass 1  count every user's events, takeovers and attack-IP events
  select  keep ALL account-takeover users, a random set of attack-IP users, and a random set of
          normal users, so the sample stays inside the dashboard limits (5 MB / 50,000 rows) and
          keeps a realistic, small share of attacks. Selected users keep their COMPLETE history,
          so per-user features are computed from real earlier behaviour.
  pass 2  pull those users' events and compute the five model features, causally (only from
          events at or before each login):
            failed_attempts  failed logins by this user in the 24 h up to and including this event
            login_hour       hour of the timestamp (0-23)
            unique_ips_24h   distinct IPs this user logged in from in the 24 h up to this event
            new_device       1 if this browser+OS+device type was never seen for this user before
            country_changed  1 if the country differs from this user's previous login
          A user's first event has no history, so new_device and country_changed are 0.
"""
from __future__ import annotations

import argparse
import sys
import time
from collections import deque
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd

WINDOW_NS = 24 * 3600 * 10**9
MAX_DASHBOARD_BYTES = 5 * 1024 * 1024
LABEL_MODES = ("either", "takeover", "attack_ip")

# canonical name -> accepted header spellings (compared lower-case, stripped)
ALIASES: dict[str, list[str]] = {
    "index": ["index", "id"],
    "timestamp": ["login timestamp", "timestamp"],
    "user": ["user id", "userid", "user"],
    "ip": ["ip address", "ip"],
    "country": ["country"],
    "browser": ["browser name and version", "browser"],
    "os": ["os name and version", "os"],
    "device": ["device type", "device"],
    "success": ["login successful", "success"],
    "attack_ip": ["is attack ip"],
    "takeover": ["is account takeover"],
}
OPTIONAL = {"index"}


def resolve_columns(header: list[str]) -> dict[str, str]:
    lookup = {h.strip().lower(): h for h in header}
    found: dict[str, str] = {}
    missing = []
    for canon, names in ALIASES.items():
        hit = next((lookup[n] for n in names if n in lookup), None)
        if hit is None and canon not in OPTIONAL:
            missing.append(f"{canon} (expected one of: {', '.join(names)})")
        elif hit is not None:
            found[canon] = hit
    if missing:
        raise SystemExit("Could not find these columns in the CSV header:\n  - " + "\n  - ".join(missing)
                         + f"\nHeader seen: {header}")
    return found


def _to_bool(s: pd.Series) -> pd.Series:
    if s.dtype == bool:
        return s
    return s.astype(str).str.strip().str.lower().isin(["true", "1", "yes"])


def _log(msg: str) -> None:
    print(msg, flush=True)


# ----------------------------------------------------------------- pass 1
def scan_users(path: Path, cols: dict[str, str], label_mode: str, chunk_rows: int) -> pd.DataFrame:
    """Per-user counts: n (events), ato, atk, pos (events that count as positive for `label_mode`)."""
    use = [cols["user"], cols["attack_ip"], cols["takeover"]]
    parts: list[pd.DataFrame] = []
    acc: Optional[pd.DataFrame] = None
    total, t0 = 0, time.time()
    try:
        reader = pd.read_csv(path, usecols=use, chunksize=chunk_rows, dtype={cols["user"]: "int64"})
        for i, chunk in enumerate(reader, 1):
            ato = _to_bool(chunk[cols["takeover"]]).to_numpy()
            atk = _to_bool(chunk[cols["attack_ip"]]).to_numpy()
            pos = {"either": ato | atk, "takeover": ato, "attack_ip": atk}[label_mode]
            part = pd.DataFrame({"user": chunk[cols["user"]].to_numpy(), "n": 1,
                                 "ato": ato.astype(np.int64), "atk": atk.astype(np.int64),
                                 "pos": pos.astype(np.int64)}).groupby("user").sum()
            parts.append(part)
            total += len(chunk)
            if len(parts) >= 8:  # consolidate so memory stays flat
                merged = pd.concat(([acc] if acc is not None else []) + parts).groupby(level=0).sum()
                acc, parts = merged, []
            _log(f"  pass 1: chunk {i}, {total:,} rows read ({time.time() - t0:,.0f}s)")
    except ValueError as exc:
        raise SystemExit(f"Could not read the User ID column as whole numbers: {exc}")
    if parts or acc is None:
        acc = pd.concat(([acc] if acc is not None else []) + parts).groupby(level=0).sum()
    return acc.astype(np.int64)


# ------------------------------------------------------------- selection
def select_users(agg: pd.DataFrame, label_mode: str, max_rows: int, positive_rate: float,
                 min_events: int, max_events: int, seed: int) -> tuple[np.ndarray, dict]:
    rng = np.random.default_rng(seed)
    if int(agg["pos"].sum()) == 0:
        raise SystemExit(f"No positive events found for --label {label_mode}; nothing to evaluate against.")
    chosen: list[np.ndarray] = []
    rows = pos_events = 0
    pos_cap = max(1, int(positive_rate * max_rows))

    if label_mode in ("either", "takeover"):  # the rare, targeted attacks: always keep every one
        ato_users = agg[agg["ato"] > 0]
        chosen.append(ato_users.index.to_numpy())
        rows += int(ato_users["n"].sum())
        pos_events += int(ato_users["pos"].sum())
    taken = np.concatenate(chosen) if chosen else np.array([], dtype=np.int64)

    cand = agg[(agg["pos"] > 0) & ~agg.index.isin(taken) & (agg["n"] <= max_events)]
    if len(cand):
        order = rng.permutation(len(cand))
        n_, p_ = cand["n"].to_numpy()[order], cand["pos"].to_numpy()[order]
        ok = (np.cumsum(p_) + pos_events <= pos_cap) & (np.cumsum(n_) + rows <= int(max_rows * 0.6))
        k = int(np.argmin(ok)) if not ok.all() else len(ok)  # longest all-True prefix
        pick = cand.index.to_numpy()[order][:k]
        chosen.append(pick)
        rows += int(n_[:k].sum())
        pos_events += int(p_[:k].sum())
    taken = np.concatenate(chosen)

    normal = agg[(agg["pos"] == 0) & ~agg.index.isin(taken) & (agg["n"] >= min_events) & (agg["n"] <= max_events)]
    if len(normal):
        order = rng.permutation(len(normal))
        n_ = normal["n"].to_numpy()[order]
        ok = np.cumsum(n_) + rows <= max_rows
        k = int(np.argmin(ok)) if not ok.all() else len(ok)
        chosen.append(normal.index.to_numpy()[order][:k])
        rows += int(n_[:k].sum())
    users = np.unique(np.concatenate(chosen))
    return users, {"users": len(users), "expected_rows": rows, "expected_positive_events": pos_events,
                   "takeover_users": int((agg.loc[users, "ato"] > 0).sum())}


# ----------------------------------------------------------------- pass 2
def gather(path: Path, cols: dict[str, str], users: np.ndarray, chunk_rows: int) -> pd.DataFrame:
    wanted = ["index", "timestamp", "user", "ip", "country", "browser", "os", "device", "success",
              "attack_ip", "takeover"]
    use = [cols[w] for w in wanted if w in cols]
    keep = np.sort(users)
    parts, total, t0 = [], 0, time.time()
    for i, chunk in enumerate(pd.read_csv(path, usecols=use, chunksize=chunk_rows,
                                          dtype={cols["user"]: "int64"}), 1):
        mask = np.isin(chunk[cols["user"]].to_numpy(), keep)
        if mask.any():
            parts.append(chunk[mask])
        total += len(chunk)
        _log(f"  pass 2: chunk {i}, {total:,} rows read, {sum(len(p) for p in parts):,} kept ({time.time() - t0:,.0f}s)")
    if not parts:
        raise SystemExit("None of the selected users were found in pass 2 (file changed between passes?).")
    raw = pd.concat(parts, ignore_index=True)
    out = pd.DataFrame({
        "idx": raw[cols["index"]].astype(str) if "index" in cols else raw.index.astype(str),
        "ts": pd.to_datetime(raw[cols["timestamp"]], errors="coerce"),
        "user": raw[cols["user"]].to_numpy(),
        "ip": raw[cols["ip"]].astype(str),
        "country": raw[cols["country"]].astype(str),
        "device_key": raw[cols["browser"]].astype(str) + "|" + raw[cols["os"]].astype(str) + "|" + raw[cols["device"]].astype(str),
        "success": _to_bool(raw[cols["success"]]).to_numpy(),
        "atk": _to_bool(raw[cols["attack_ip"]]).to_numpy(),
        "ato": _to_bool(raw[cols["takeover"]]).to_numpy(),
    })
    bad = int(out["ts"].isna().sum())
    if bad:
        _log(f"  warning: dropped {bad} rows with unreadable timestamps")
        out = out.dropna(subset=["ts"])
    return out


# --------------------------------------------------------------- features
def build_features(df: pd.DataFrame, label_mode: str = "either") -> pd.DataFrame:
    """Causal per-user features. `df` needs idx, ts, user, ip, country, device_key, success, atk, ato."""
    df = df.sort_values(["user", "ts", "idx"], kind="mergesort").reset_index(drop=True)
    # pandas >= 3 keeps microseconds; force nanoseconds so the 24 h window is exact on every version
    ts_ns = df["ts"].to_numpy(dtype="datetime64[ns]").astype("int64")
    n = len(df)
    failed = np.zeros(n, dtype=np.int64)
    ips = np.zeros(n, dtype=np.int64)
    new_dev = np.zeros(n, dtype=np.int64)
    cc = np.zeros(n, dtype=np.int64)

    users = df["user"].to_numpy()
    success = df["success"].to_numpy()
    ip_col, country_col, dev_col = df["ip"].to_numpy(), df["country"].to_numpy(), df["device_key"].to_numpy()
    start = 0
    while start < n:
        end = start
        while end < n and users[end] == users[start]:
            end += 1
        fails: deque[int] = deque()
        recent: deque[tuple[int, str]] = deque()
        seen_dev: set[str] = set()
        prev_country: Optional[str] = None
        for i in range(start, end):
            t = ts_ns[i]
            while fails and fails[0] < t - WINDOW_NS:
                fails.popleft()
            while recent and recent[0][0] < t - WINDOW_NS:
                recent.popleft()
            if not success[i]:
                fails.append(t)
            recent.append((t, ip_col[i]))
            failed[i] = len(fails)
            ips[i] = len({ip for _, ip in recent})
            if i > start:  # first event of a user has no history to compare with
                new_dev[i] = int(dev_col[i] not in seen_dev)
                cc[i] = int(country_col[i] != prev_country)
            seen_dev.add(dev_col[i])
            prev_country = country_col[i]
        start = end

    ato, atk = df["ato"].to_numpy(), df["atk"].to_numpy()
    label = {"either": ato | atk, "takeover": ato, "attack_ip": atk}[label_mode].astype(int)
    rank = {u: r for r, u in enumerate(np.sort(df["user"].unique()), 1)}
    out = pd.DataFrame({
        "event_id": "rba_" + df["idx"],
        "timestamp": df["ts"].dt.strftime("%Y-%m-%d %H:%M:%S"),
        "username": ["user_%05d" % rank[u] for u in df["user"]],
        "source_ip": df["ip"],
        "failed_attempts": failed,
        "login_hour": df["ts"].dt.hour.to_numpy(),
        "unique_ips_24h": ips,
        "new_device": new_dev,
        "country_changed": cc,
        "label": label,
        "attack_type": np.where(ato, "account_takeover", np.where(atk, "attack_ip", "none")),
        "_ts": df["ts"],
    })
    return out.sort_values(["_ts", "event_id"], kind="mergesort").drop(columns="_ts").reset_index(drop=True)


# ------------------------------------------------------------------- main
def run(src: Path, out: Path, label_mode: str = "either", max_rows: int = 30_000, positive_rate: float = 0.03,
        min_events: int = 5, max_events: int = 200, seed: int = 42, chunk_rows: int = 1_000_000) -> pd.DataFrame:
    header = list(pd.read_csv(src, nrows=0).columns)
    cols = resolve_columns(header)
    _log(f"Input: {src} ({src.stat().st_size / 1e9:.2f} GB)\nPass 1: counting events per user...")
    agg = scan_users(src, cols, label_mode, chunk_rows)
    _log(f"  {len(agg):,} users, {int(agg['n'].sum()):,} events, {int(agg['ato'].sum()):,} account takeovers, "
         f"{int(agg['atk'].sum()):,} attack-IP events")
    users, plan = select_users(agg, label_mode, max_rows, positive_rate, min_events, max_events, seed)
    _log(f"Selected {plan['users']:,} users (~{plan['expected_rows']:,} rows, {plan['takeover_users']} with a takeover)."
         "\nPass 2: collecting their full histories...")
    feats = build_features(gather(src, cols, users, chunk_rows), label_mode)
    out.parent.mkdir(parents=True, exist_ok=True)
    feats.to_csv(out, index=False, lineterminator="\n")
    size = out.stat().st_size
    pos = int(feats["label"].sum())
    _log(f"\nWrote {out}\n  rows: {len(feats):,}   users: {feats['username'].nunique():,}   size: {size / 1e6:.2f} MB"
         f"\n  positives (label=1): {pos:,} ({pos / len(feats):.1%})   takeovers: {int((feats['attack_type'] == 'account_takeover').sum())}"
         f"   attack-IP: {int((feats['attack_type'] == 'attack_ip').sum())}")
    if size > MAX_DASHBOARD_BYTES or len(feats) > 50_000:
        _log("  WARNING: over the dashboard limit (5 MB / 50,000 rows). Re-run with a smaller --max-rows.")
    else:
        _log("Next: upload this file in the dashboard, choose Model mode = Batch, and click Analyze.")
    return feats


def main(argv: Optional[list[str]] = None) -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("input", type=Path, help="path to rba-dataset.csv")
    p.add_argument("--out", type=Path, default=Path("../data/rba_sample.csv"))
    p.add_argument("--label", choices=LABEL_MODES, default="either",
                   help="what counts as label=1: account takeover, attack-IP login, or either (default)")
    p.add_argument("--max-rows", type=int, default=30_000, help="target sample size (dashboard limit 50,000 rows / 5 MB)")
    p.add_argument("--positive-rate", type=float, default=0.03, help="max share of positive events in the sample")
    p.add_argument("--min-events", type=int, default=5, help="normal users need at least this many events (history)")
    p.add_argument("--max-events", type=int, default=200, help="skip users with more events than this")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--chunk-rows", type=int, default=1_000_000, help="rows per chunk; lower it if memory is tight")
    a = p.parse_args(argv)
    if not a.input.exists():
        sys.exit(f"File not found: {a.input}")
    if not 0 < a.positive_rate < 0.5:
        sys.exit("--positive-rate must be between 0 and 0.5")
    run(a.input, a.out, a.label, a.max_rows, a.positive_rate, a.min_events, a.max_events, a.seed, a.chunk_rows)


if __name__ == "__main__":
    main()
