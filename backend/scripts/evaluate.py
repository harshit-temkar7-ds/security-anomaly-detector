"""Compare Isolation Forest with a transparent rule baseline on a held-out synthetic test set.

Usage (from backend/):  python -m scripts.evaluate
The test set uses a different seed from training and the label is never a model input.
Metrics on synthetic data do NOT prove real-world effectiveness.
"""
from __future__ import annotations

from app.config import FEATURES
from app.evaluation import compute_metrics
from app.model import get_bundle, score
from app.rules import rule_flags
from app.synthetic import generate_login_events


def show(name: str, m: dict) -> None:
    c = m["confusion_matrix"]
    print(f"{name:<16} precision={m['precision']:.3f} recall={m['recall']:.3f} f1={m['f1']:.3f} "
          f"auc={m['roc_auc']}  TP={c['tp']} FP={c['fp']} FN={c['fn']} TN={c['tn']}")


def main() -> None:
    test = generate_login_events(n=10_000, anomaly_rate=0.04, seed=2026)
    X, y = test[FEATURES], test["label"].to_numpy()
    print(f"Test set: {len(test)} rows, {int(y.sum())} simulated attacks, model {get_bundle()['version']}\n")

    s, flags, thr, _ = score(X, "baseline")
    show("IsolationForest", compute_metrics(y, flags, s))
    show("Rules", compute_metrics(y, rule_flags(X).to_numpy()))

    test = test.assign(pred=flags)
    print("\nRecall by simulated attack type (what does the model miss?):")
    for kind, g in test[test["label"] == 1].groupby("attack_type"):
        print(f"  {kind:<20} {g['pred'].mean():.3f}  (n={len(g)})")
    fp = test[(test["label"] == 0) & test["pred"]]
    print(f"\nFalse positives: {len(fp)} - inspect them for common patterns, e.g. legitimate travellers.")


if __name__ == "__main__":
    main()
