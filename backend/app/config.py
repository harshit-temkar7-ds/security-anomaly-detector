"""Central configuration. Override via environment variables where noted."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parent.parent
PROJECT_DIR = BACKEND_DIR.parent


def load_backend_dotenv(path: Path | None = None) -> None:
    """Load the backend's local environment file without overriding process settings."""
    env_path = path or (Path(__file__).resolve().parents[1] / ".env")
    load_dotenv(env_path, override=False)


# Tests set this before importing the app; they use isolated fake values instead.
if os.getenv("SAD_TESTING") != "1":
    load_backend_dotenv()

# Model inputs. The `label` column is NEVER part of this list (no label leakage).
FEATURES: list[str] = [
    "failed_attempts",
    "login_hour",
    "unique_ips_24h",
    "new_device",
    "country_changed",
]
BINARY_FEATURES = ["new_device", "country_changed"]
COUNT_FEATURES = ["failed_attempts", "unique_ips_24h"]
LABEL_COLUMN = "label"
RANDOM_SEED = 42


def _origins() -> list[str]:
    raw = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    if not origins or "*" in origins:
        return ["http://localhost:5173", "http://127.0.0.1:5173"]
    return origins


STATUSES = ["new", "in_review", "escalated", "false_positive", "resolved"]
DEFAULT_UBA_MIN_HISTORY = 10


def _db_path() -> Path:
    # Override with SAD_DB_PATH (e.g. for tests or a different disk). Never commit the .db file.
    env = os.getenv("SAD_DB_PATH")
    return Path(env) if env else PROJECT_DIR / "var" / "scans.db"


@dataclass
class Settings:
    max_file_bytes: int = 5 * 1024 * 1024
    max_rows: int = 50_000
    max_stored_scans: int = 500  # retention: oldest scans are pruned beyond this
    db_path: Path = field(default_factory=_db_path)
    model_path: Path = BACKEND_DIR / "models" / "isolation_forest.joblib"
    triage_path: Path = BACKEND_DIR / "models" / "triage.joblib"
    sample_path: Path = PROJECT_DIR / "data" / "sample_login_events.csv"
    cors_origins: list[str] = field(default_factory=_origins)


settings = Settings()
