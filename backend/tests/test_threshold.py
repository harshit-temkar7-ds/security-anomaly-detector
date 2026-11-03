import numpy as np
import pytest

from app.synthetic import generate_login_events

from .conftest import post_csv


def flagged(client, sid):
    return client.get(f"/api/scans/{sid}").json()["anomalies_flagged"]


def test_analyze_accepts_threshold(client, synth_csv):
    low = post_csv(client, synth_csv, threshold=0.50).json()
    high = post_csv(client, synth_csv, threshold=0.75).json()
    assert low["anomalies_flagged"] > high["anomalies_flagged"]
    assert low["threshold"] == 0.5 and low["model_threshold"] != 0.5
    assert all(r["is_anomaly"] == (r["anomaly_score"] >= 0.5) for r in low["results"])


@pytest.mark.parametrize("bad", ["0", "1", "-0.2", "1.5", "abc"])
def test_invalid_threshold_rejected(client, synth_csv, bad):
    assert post_csv(client, synth_csv, threshold=bad).status_code == 422


def test_evaluate_previews_without_changing_scan(client, scan_id):
    before = flagged(client, scan_id)
    ev = client.get(f"/api/scans/{scan_id}/evaluate", params={"threshold": 0.7}).json()
    assert ev["threshold"] == 0.7 and ev["flagged"] < before
    assert flagged(client, scan_id) == before            # preview only
    assert client.get(f"/api/scans/{scan_id}").json()["threshold"] == ev["active_threshold"]


def test_put_threshold_updates_flags_metrics_and_severity(client, scan_id):
    base = client.get(f"/api/scans/{scan_id}").json()
    r = client.put(f"/api/scans/{scan_id}/threshold", json={"threshold": 0.72})
    assert r.status_code == 200
    new = client.get(f"/api/scans/{scan_id}").json()
    assert new["threshold"] == 0.72 and new["anomalies_flagged"] < base["anomalies_flagged"]
    assert new["evaluation"]["model"]["recall"] <= base["evaluation"]["model"]["recall"]
    assert new["evaluation"]["rules"] == base["evaluation"]["rules"]     # rules do not depend on threshold
    assert sum(new["severity_counts"].values()) == new["anomalies_flagged"]
    assert sum(h["flagged"] for h in new["hourly"]) == new["anomalies_flagged"]
    assert client.get(f"/api/scans/{scan_id}/alerts").json()["total"] == new["anomalies_flagged"]


def test_put_threshold_validation(client, scan_id):
    for bad in (0, 1, -1, 2, "x", None):
        assert client.put(f"/api/scans/{scan_id}/threshold", json={"threshold": bad}).status_code == 422
    assert client.put("/api/scans/nope/threshold", json={"threshold": 0.5}).status_code == 404


def test_compares_model_against_rule_baseline(client, scan_id):
    ev = client.get(f"/api/scans/{scan_id}/evaluate").json()
    assert {"model", "rules"} <= set(ev["evaluation"])
    ag = ev["agreement"]
    assert sum(ag.values()) == 1500 and ag["both"] + ag["rules_only"] == ev["rule_flags"]
    assert len(ev["sweep"]) == 40 and ev["sweep"][0]["flagged"] >= ev["sweep"][-1]["flagged"]


def test_no_label_leakage_scores_flags_and_suggestions(client):
    df = generate_login_events(n=1200, anomaly_rate=0.05, seed=5)
    labeled = post_csv(client, df.to_csv(index=False)).json()
    unlabeled = post_csv(client, df.drop(columns=["label", "attack_type"]).to_csv(index=False)).json()
    # identical scores and flags with or without labels in the file
    assert [r["anomaly_score"] for r in labeled["results"]] == [r["anomaly_score"] for r in unlabeled["results"]]
    assert labeled["threshold"] == unlabeled["threshold"]
    assert labeled["anomalies_flagged"] == unlabeled["anomalies_flagged"]
    a = client.get(f"/api/scans/{labeled['scan_id']}/evaluate").json()
    b = client.get(f"/api/scans/{unlabeled['scan_id']}/evaluate").json()
    assert a["suggestions"] == b["suggestions"] and a["agreement"] == b["agreement"]
    assert unlabeled["evaluation"] is None and b["evaluation"] is None
    assert all(p["precision"] is None for p in b["sweep"])


def test_shuffled_labels_do_not_change_flags(client):
    df = generate_login_events(n=800, anomaly_rate=0.05, seed=8)
    shuffled = df.assign(label=np.random.default_rng(0).permutation(df["label"].to_numpy()))
    a = post_csv(client, df.to_csv(index=False)).json()
    b = post_csv(client, shuffled.to_csv(index=False)).json()
    assert a["anomalies_flagged"] == b["anomalies_flagged"]
    assert a["evaluation"]["model"] != b["evaluation"]["model"]     # only the metrics differ


def test_metrics_follow_the_threshold(client, scan_id):
    hi = client.get(f"/api/scans/{scan_id}/evaluate", params={"threshold": 0.9}).json()
    assert hi["flagged"] == 0 and hi["evaluation"]["model"]["recall"] == 0
    lo = client.get(f"/api/scans/{scan_id}/evaluate", params={"threshold": 0.01}).json()
    assert lo["flagged"] == 1500 and lo["evaluation"]["model"]["recall"] == 1
