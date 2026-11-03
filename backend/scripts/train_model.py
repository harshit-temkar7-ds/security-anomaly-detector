"""Train and save the baseline Isolation Forest.

Usage (from backend/):  python -m scripts.train_model
"""
from __future__ import annotations

from app.config import settings
from app.model import save_bundle, train_baseline


def main() -> None:
    bundle = train_baseline()
    save_bundle(bundle)
    print(f"Saved {bundle['version']} -> {settings.model_path}")
    print(f"Threshold {bundle['threshold']:.4f} (flags ~{bundle['flag_rate']:.0%} of baseline events)")


if __name__ == "__main__":
    main()
