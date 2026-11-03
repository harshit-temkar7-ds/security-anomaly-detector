import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Prevent a developer's backend/.env from entering test processes, even at import time.
os.environ["SAD_TESTING"] = "1"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def clean_llm_environment(monkeypatch):
    """Tests never inherit local LLM credentials or settings."""
    for name in ("SAD_LLM_ENABLED", "GEMINI_API_KEY", "SAD_LLM_MODEL", "SAD_LLM_TIMEOUT"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    """Every test gets its own throw-away SQLite file; the real database is never touched."""
    monkeypatch.setattr(settings, "db_path", tmp_path / "test_scans.db")


@pytest.fixture(autouse=True)
def temp_triage(tmp_path, monkeypatch):
    """The feedback (triage) model file is per-test too, so tests never touch backend/models."""
    from app import triage
    monkeypatch.setattr(settings, "triage_path", tmp_path / "triage.joblib")
    triage._reset_cache()
    yield
    triage._reset_cache()


@pytest.fixture()
def client():
    return TestClient(app)


GOOD_CSV = (
    "failed_attempts,login_hour,unique_ips_24h,new_device,country_changed\n"
    "0,10,1,0,0\n1,11,1,0,0\n0,14,1,0,0\n0,9,1,0,0\n2,15,2,0,0\n"
    "0,13,1,0,0\n1,12,1,1,0\n0,10,1,0,0\n25,3,9,1,1\n0,16,1,0,0\n"
)


def post_csv(client, text, name="events.csv", **params):
    return client.post("/api/analyze", files={"file": (name, text.encode(), "text/csv")}, params=params)


import pandas as pd  # noqa: E402

from app.synthetic import generate_login_events  # noqa: E402


@pytest.fixture()
def synth_csv():
    return generate_login_events(n=1500, anomaly_rate=0.05, seed=11).to_csv(index=False)


@pytest.fixture()
def scan_id(client, synth_csv):
    r = post_csv(client, synth_csv, name="synthetic.csv")
    assert r.status_code == 200
    return r.json()["scan_id"]


def make_user_csv(spike: bool = True, n_stable: int = 30, user: str = "alice") -> str:
    """One user with a stable pattern (daytime, ~0 failures, one device), optionally followed by a spike."""
    rows = []
    for i in range(n_stable):
        ts = pd.Timestamp("2026-02-01") + pd.Timedelta(days=i, hours=9 + i % 8)   # one login per day, chronological
        rows.append({"timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"), "username": user,
                     "failed_attempts": i % 2, "login_hour": 9 + i % 8, "unique_ips_24h": 1,
                     "new_device": 0, "country_changed": 0})
    if spike:
        rows.append({"timestamp": "2026-03-20 03:00:00", "username": user, "failed_attempts": 20,
                     "login_hour": 3, "unique_ips_24h": 8, "new_device": 1, "country_changed": 1})
    return pd.DataFrame(rows).to_csv(index=False)
