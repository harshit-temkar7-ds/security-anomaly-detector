"""Generate fictional login events.

Usage (from backend/):  python -m scripts.generate_data
Writes data/sample_login_events.csv (labeled) and data/sample_unlabeled.csv.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from app.config import PROJECT_DIR
from app.synthetic import generate_login_events


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--rows", type=int, default=3000)
    p.add_argument("--anomaly-rate", type=float, default=0.04)
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--out-dir", type=Path, default=PROJECT_DIR / "data")
    a = p.parse_args()

    a.out_dir.mkdir(parents=True, exist_ok=True)
    df = generate_login_events(a.rows, a.anomaly_rate, a.seed)
    df.to_csv(a.out_dir / "sample_login_events.csv", index=False)
    df.drop(columns=["label", "attack_type"]).to_csv(a.out_dir / "sample_unlabeled.csv", index=False)
    print(f"Wrote {len(df)} rows ({int(df['label'].sum())} simulated attacks) to {a.out_dir}")


if __name__ == "__main__":
    main()
