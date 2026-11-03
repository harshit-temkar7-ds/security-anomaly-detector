import sqlite3

from app import store
from app.config import settings

from .conftest import GOOD_CSV, post_csv


def test_tests_use_temporary_database(tmp_path):
    assert settings.db_path.parent == tmp_path
    assert "var" not in settings.db_path.parts[-2:]


def test_scan_persisted_with_model_metadata(client, scan_id):
    row = sqlite3.connect(settings.db_path).execute(
        "SELECT model_version, model_threshold, threshold, has_labels, rows_analyzed FROM scans").fetchone()
    assert row[0].startswith("if-") and 0 < row[1] < 1 and row[2] == row[1] and row[3] == 1 and row[4] == 1500
    n = sqlite3.connect(settings.db_path).execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert n == 1500


def test_survives_restart(client, scan_id):
    first = client.get(f"/api/scans/{scan_id}").json()
    store._initialised.clear()          # simulate a fresh process: schema re-check, data must remain
    again = client.get(f"/api/scans/{scan_id}").json()
    assert again["results"] == first["results"] and again["evaluation"] == first["evaluation"]


def test_get_scan_matches_analyze_response(client, synth_csv):
    posted = post_csv(client, synth_csv).json()
    fetched = client.get(f"/api/scans/{posted['scan_id']}").json()
    assert posted == fetched


def test_history_pagination_and_order(client):
    ids = [post_csv(client, GOOD_CSV, name=f"f{i}.csv").json()["scan_id"] for i in range(5)]
    p1 = client.get("/api/history", params={"page": 1, "page_size": 2}).json()
    p3 = client.get("/api/history", params={"page": 3, "page_size": 2}).json()
    assert p1["total"] == 5 and [i["scan_id"] for i in p1["items"]] == ids[::-1][:2]
    assert [i["scan_id"] for i in p3["items"]] == [ids[0]]
    assert {"filename", "model_version", "threshold", "anomalies_flagged"} <= set(p1["items"][0])


def test_history_search_is_parameterised(client):
    post_csv(client, GOOD_CSV, name="alpha.csv")
    post_csv(client, GOOD_CSV, name="beta.csv")
    assert client.get("/api/history", params={"q": "alp"}).json()["total"] == 1
    assert client.get("/api/history", params={"q": "' OR 1=1 --"}).json()["total"] == 0
    assert client.get("/api/history", params={"q": "%"}).json()["total"] == 0   # wildcard is escaped


def test_history_validation(client):
    assert client.get("/api/history", params={"page": 0}).status_code == 422
    assert client.get("/api/history", params={"page_size": 1000}).status_code == 422


def test_status_and_notes_persist(client, scan_id):
    top = client.get(f"/api/scans/{scan_id}/alerts").json()["items"][0]["row"]
    client.patch(f"/api/scans/{scan_id}/alerts/{top}", json={"status": "escalated"})
    client.post(f"/api/scans/{scan_id}/alerts/{top}/notes", json={"note": "checked with owner"})
    store._initialised.clear()
    d = client.get(f"/api/scans/{scan_id}/alerts/{top}").json()
    assert d["status"] == "escalated" and d["notes"][0]["note"] == "checked with owner"
    assert d["status_updated_at"]


def test_delete_cascades(client, scan_id):
    assert client.delete(f"/api/scans/{scan_id}").status_code == 204
    assert client.get(f"/api/scans/{scan_id}").status_code == 404
    db = sqlite3.connect(settings.db_path)
    assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
    assert client.delete(f"/api/scans/{scan_id}").status_code == 404


def test_retention_prunes_oldest(client, monkeypatch):
    monkeypatch.setattr(settings, "max_stored_scans", 3)
    ids = [post_csv(client, GOOD_CSV).json()["scan_id"] for _ in range(5)]
    kept = [s["scan_id"] for s in client.get("/api/scans").json()]
    assert kept == ids[::-1][:3]


def test_legacy_scans_list_still_a_plain_list(client, scan_id):
    body = client.get("/api/scans").json()
    assert isinstance(body, list) and body[0]["scan_id"] == scan_id
