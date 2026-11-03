import pytest

from app.config import settings
from app.config import _origins
from app.synthetic import generate_login_events

from .conftest import GOOD_CSV, post_csv


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_analyze_valid(client):
    r = post_csv(client, GOOD_CSV)
    assert r.status_code == 200
    body = r.json()
    assert body["rows_analyzed"] == 10
    assert len(body["results"]) == 10
    assert len(body["hourly"]) == 24
    assert body["evaluation"] is None
    first = body["results"][0]
    assert {"is_anomaly", "anomaly_score", "review_reason", "rule_flag"} <= set(first)
    # sorted most-anomalous first; the extreme row should be on top
    assert first["failed_attempts"] == 25 and first["is_anomaly"] is True


def test_batch_mode(client):
    r = post_csv(client, GOOD_CSV, mode="batch")
    assert r.status_code == 200 and r.json()["model_version"] == "batch-fit"


def test_invalid_mode(client):
    assert post_csv(client, GOOD_CSV, mode="nope").status_code == 422


def test_missing_columns(client):
    r = post_csv(client, "failed_attempts,login_hour\n1,2\n")
    assert r.status_code == 422
    assert "unique_ips_24h" in r.json()["detail"]["missing"]


def test_non_numeric(client):
    bad = GOOD_CSV.replace("0,10,1,0,0", "abc,10,1,0,0", 1)
    assert post_csv(client, bad).status_code == 422


@pytest.mark.parametrize("column,value", [
    ("failed_attempts", "1.5"), ("login_hour", "3.5"), ("unique_ips_24h", "2.5"),
])
def test_fractional_features_are_rejected(client, column, value):
    header = "failed_attempts,login_hour,unique_ips_24h,new_device,country_changed"
    row = {"failed_attempts": "0", "login_hour": "10", "unique_ips_24h": "1",
           "new_device": "0", "country_changed": "0"}
    row[column] = value
    csv = header + "\n" + ",".join(row[c] for c in header.split(","))
    assert post_csv(client, csv).status_code == 422


def test_blank_value(client):
    bad = GOOD_CSV.replace("0,10,1,0,0", ",10,1,0,0", 1)
    assert post_csv(client, bad).status_code == 422


@pytest.mark.parametrize(
    "row",
    ["0,24,1,0,0", "0,-1,1,0,0", "-1,10,1,0,0", "0,10,-2,0,0", "0,10,1,2,0", "0,10,1,0,5"],
)
def test_out_of_range(client, row):
    bad = GOOD_CSV.replace("0,10,1,0,0", row, 1)
    assert post_csv(client, bad).status_code == 422


def test_empty_csv(client):
    r = post_csv(client, "failed_attempts,login_hour,unique_ips_24h,new_device,country_changed\n")
    assert r.status_code == 400


def test_not_csv_extension(client):
    assert post_csv(client, GOOD_CSV, name="events.txt").status_code == 400


def test_garbage_bytes(client):
    r = client.post("/api/analyze", files={"file": ("x.csv", b"\xff\xfe\x00bad", "text/csv")})
    assert r.status_code in (400, 422)


def test_oversized_file(client, monkeypatch):
    monkeypatch.setattr(settings, "max_file_bytes", 100)
    assert post_csv(client, GOOD_CSV).status_code == 413


def test_too_many_rows(client, monkeypatch):
    monkeypatch.setattr(settings, "max_rows", 3)
    assert post_csv(client, GOOD_CSV).status_code == 413


def test_labels_produce_metrics_and_are_not_features(client):
    df = generate_login_events(n=1500, anomaly_rate=0.05, seed=99)
    r = post_csv(client, df.to_csv(index=False))
    assert r.status_code == 200
    ev = r.json()["evaluation"]
    assert ev["positives"] == int(df["label"].sum())
    assert 0 <= ev["model"]["precision"] <= 1 and 0 <= ev["model"]["recall"] <= 1
    assert ev["model"]["recall"] > 0.5  # sanity: detector beats chance on synthetic data
    cm = ev["model"]["confusion_matrix"]
    assert sum(cm.values()) == len(df)
    # passthrough columns are returned untouched
    assert "username" in r.json()["results"][0]


def test_invalid_label_values(client):
    bad = GOOD_CSV.replace("new_device,country_changed\n", "new_device,country_changed,label\n", 1)
    lines = bad.strip().split("\n")
    rows = [lines[0]] + [f"{l},7" for l in lines[1:]]
    assert post_csv(client, "\n".join(rows)).status_code == 422


def test_scan_history(client):
    scan_id = post_csv(client, GOOD_CSV).json()["scan_id"]
    assert client.get(f"/api/scans/{scan_id}").json()["scan_id"] == scan_id
    assert [s["scan_id"] for s in client.get("/api/scans").json()] == [scan_id]
    assert client.get("/api/scans/doesnotexist").status_code == 404


def test_store_is_bounded(client, monkeypatch):
    monkeypatch.setattr(settings, "max_stored_scans", 2)
    for _ in range(4):
        post_csv(client, GOOD_CSV)
    assert len(client.get("/api/scans").json()) == 2


def test_cors_allows_dev_origin(client):
    r = client.options(
        "/api/analyze",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"},
    )
    assert r.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_cors_wildcard_configuration_falls_back_to_explicit_origins(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "*,https://example.invalid")
    origins = _origins()
    assert origins == ["http://localhost:5173", "http://127.0.0.1:5173"]
    assert "*" not in origins


def test_cors_exposes_llm_used_header(client):
    r = client.get("/api/config", headers={"Origin": "http://localhost:5173"})
    exposed = r.headers["access-control-expose-headers"].lower()
    assert "x-llm-used" in exposed and "x-llm-reason" in exposed
