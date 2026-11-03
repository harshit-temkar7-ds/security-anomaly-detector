from app.config import FEATURES
from app.evaluation import compute_metrics
from app import model as model_module
from app.model import get_bundle, score
from app.config import settings
from app.rules import review_reasons, rule_flags
from app.synthetic import generate_login_events


def test_synthetic_is_reproducible():
    a = generate_login_events(500, 0.05, seed=1)
    b = generate_login_events(500, 0.05, seed=1)
    assert a.equals(b)
    assert int(a["label"].sum()) == 25


def test_label_not_a_feature():
    assert "label" not in FEATURES and "attack_type" not in FEATURES
    assert "label" not in get_bundle()["features"]


def test_model_beats_chance_on_holdout():
    test = generate_login_events(5000, 0.04, seed=2026)
    s, flags, _, _ = score(test[FEATURES])
    m = compute_metrics(test["label"], flags, s)
    assert m["roc_auc"] > 0.85 and m["recall"] > 0.5


def test_rules_and_reasons():
    df = generate_login_events(300, 0.1, seed=3)[FEATURES]
    assert rule_flags(df).dtype == bool
    assert review_reasons(df).str.len().min() > 0


def test_metrics_zero_division_safe():
    m = compute_metrics([0, 0, 0], [0, 0, 0])
    assert m["precision"] == 0 and m["recall"] == 0 and m["roc_auc"] is None


def test_corrupt_saved_model_retrains_and_analysis_scores(tmp_path, monkeypatch):
    model_path = tmp_path / "isolation_forest.joblib"
    model_path.write_bytes(b"incompatible model data")
    monkeypatch.setattr(settings, "model_path", model_path)
    original_train = model_module.train_baseline
    monkeypatch.setattr(model_module, "train_baseline", lambda: original_train(n=100))
    get_bundle.cache_clear()
    try:
        sample = generate_login_events(30, seed=17)[FEATURES]
        scores, flags, threshold, version = score(sample)
        assert len(scores) == len(flags) == len(sample)
        assert threshold > 0 and version.startswith("if-")
        assert model_path.stat().st_size > len(b"incompatible model data")
    finally:
        get_bundle.cache_clear()
