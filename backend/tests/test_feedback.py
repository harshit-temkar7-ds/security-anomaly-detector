import pytest

from app import triage
from app.config import settings
from app.synthetic import generate_login_events

from .conftest import post_csv


def _review(client, scan_id, n_each=15):
    """Act like an analyst: false_positive for benign flagged alerts, escalated for attacks."""
    done = {"false_positive": 0, "escalated": 0}
    page = 1
    while min(done.values()) < n_each:
        body = client.get(f"/api/scans/{scan_id}/alerts?detector=either&page_size=100&page={page}").json()
        if not body["items"]:
            break
        for it in body["items"]:
            status = "escalated" if it["data"]["label"] == 1 else "false_positive"
            if done[status] < n_each and it["status"] == "new":
                client.patch(f"/api/scans/{scan_id}/alerts/{it['row']}", json={"status": status}).raise_for_status()
                done[status] += 1
        page += 1
    return done


@pytest.fixture()
def big_scan(client):
    csv = generate_login_events(n=4000, anomaly_rate=0.05, seed=21).to_csv(index=False)
    return post_csv(client, csv, name="big.csv").json()["scan_id"]


def test_summary_without_feedback(client, scan_id):
    s = client.get("/api/feedback/summary").json()
    assert s["active"] is None and s["can_train"] is False and s["still_needed"]["escalated"] == triage.MIN_PER_CLASS


def test_training_needs_enough_feedback(client, scan_id):
    r = client.post("/api/feedback/train", json={"activate": True}).json()
    assert r["status"] == "insufficient_feedback" and r["activated"] is False
    assert not settings.triage_path.exists()


def test_preview_does_not_activate(client, big_scan):
    _review(client, big_scan)
    r = client.post("/api/feedback/train", json={}).json()
    assert r["status"] == "ok" and r["activated"] is False and r["cv"]["roc_auc"] > 0.9
    assert not settings.triage_path.exists() and r["drivers"]


def test_activation_adds_learned_priority_and_rollback(client, big_scan):
    _review(client, big_scan)
    before = client.get(f"/api/scans/{big_scan}/alerts?page_size=5").json()["items"]
    assert all(i["triage"] is None for i in before)

    r = client.post("/api/feedback/train", json={"activate": True}).json()
    assert r["activated"] and r["passed_gate"] and settings.triage_path.exists()

    after = client.get(f"/api/scans/{big_scan}/alerts?page_size=100").json()["items"]
    assert all(0 <= i["triage"] <= 1 and i["triage_label"] for i in after)
    sus = [i["triage"] for i in after if i["data"]["label"] == 1]
    ben = [i["triage"] for i in after if i["data"]["label"] == 0]
    assert sum(sus) / len(sus) > sum(ben) / len(ben) + 0.4   # learned the analysts' distinction
    detail = client.get(f"/api/scans/{big_scan}/alerts/{after[0]['row']}").json()
    assert detail["triage"] is not None

    s = client.get("/api/feedback/summary").json()
    assert s["active"]["version"].startswith("tri-") and s["active"]["trained_on"]["escalated"] == 15

    assert client.post("/api/feedback/rollback").json()["status"] == "disabled"
    assert not settings.triage_path.exists()
    again = client.get(f"/api/scans/{big_scan}/alerts?page_size=5").json()["items"]
    assert all(i["triage"] is None for i in again)


def test_second_activation_keeps_previous_for_rollback(client, big_scan):
    _review(client, big_scan)
    v1 = client.post("/api/feedback/train", json={"activate": True}).json()["version"]
    _review(client, big_scan, n_each=30)
    client.post("/api/feedback/train", json={"activate": True})
    assert client.get("/api/feedback/summary").json()["has_previous"] is True
    rb = client.post("/api/feedback/rollback").json()
    assert rb["status"] == "restored_previous" and rb["active_version"] == v1


def test_quality_gate_blocks_noise(client, big_scan):
    """Analyst decisions unrelated to the data (coin flips) must not produce an activated model."""
    import random
    rng = random.Random(0)
    items = client.get(f"/api/scans/{big_scan}/alerts?detector=either&page_size=100").json()["items"]
    for it in items[:80]:
        client.patch(f"/api/scans/{big_scan}/alerts/{it['row']}",
                     json={"status": rng.choice(["escalated", "false_positive"])}).raise_for_status()
    r = client.post("/api/feedback/train", json={"activate": True}).json()
    assert r["status"] == "ok" and r["passed_gate"] is False and r["activated"] is False
    assert r["blocked_reasons"] and not settings.triage_path.exists()


def test_damaged_model_file_does_not_break_alerts(client, big_scan):
    settings.triage_path.write_bytes(b"not a model")
    triage._reset_cache()
    r = client.get(f"/api/scans/{big_scan}/alerts?page_size=3")
    assert r.status_code == 200 and all(i["triage"] is None for i in r.json()["items"])


def test_rollback_with_nothing_to_do(client):
    assert client.post("/api/feedback/rollback").json()["status"] == "nothing_to_roll_back"


def test_nl_search_and_copilot_show_learned_priority(client, big_scan):
    _review(client, big_scan)
    client.post("/api/feedback/train", json={"activate": True})
    body = client.post(f"/api/scans/{big_scan}/nl-search", json={"query": "critical"}).json()
    assert all(i["triage"] is not None for i in body["items"])
    ans = client.post(f"/api/scans/{big_scan}/copilot", json={"question": "what has the feedback model learned?"}).json()
    assert "tri-" in ans["answer"]
