"""Strict CSV parsing and schema validation. Raises HTTPException with clear messages."""
from __future__ import annotations

from io import StringIO

import numpy as np
import pandas as pd
from fastapi import HTTPException

from .config import BINARY_FEATURES, COUNT_FEATURES, FEATURES, LABEL_COLUMN, settings


def parse_csv(filename: str | None, raw: bytes) -> pd.DataFrame:
    if not filename or not filename.lower().endswith(".csv"):
        raise HTTPException(400, "Upload a CSV file (.csv).")
    if len(raw) > settings.max_file_bytes:
        raise HTTPException(413, f"File exceeds {settings.max_file_bytes // (1024 * 1024)} MB limit.")
    try:
        df = pd.read_csv(StringIO(raw.decode("utf-8-sig")))
    except (UnicodeDecodeError, pd.errors.ParserError, pd.errors.EmptyDataError):
        raise HTTPException(400, "Could not parse the file as a UTF-8 CSV.")
    if df.empty:
        raise HTTPException(400, "CSV contains no rows.")
    if len(df) > settings.max_rows:
        raise HTTPException(413, f"Maximum {settings.max_rows} rows allowed.")
    return df


def validate_features(df: pd.DataFrame) -> pd.DataFrame:
    """Return a clean numeric feature frame (columns = FEATURES) or raise 422."""
    missing = [c for c in FEATURES if c not in df.columns]
    if missing:
        raise HTTPException(422, {"message": "Missing required feature columns", "missing": missing})

    X = df[FEATURES].apply(pd.to_numeric, errors="coerce")
    if X.isna().any().any() or not np.isfinite(X.to_numpy(dtype=float)).all():
        raise HTTPException(422, "Feature columns must contain finite numeric values with no blanks.")
    if (X % 1 != 0).any().any():
        raise HTTPException(422, "Feature columns must contain whole numbers.")
    if ((X["login_hour"] < 0) | (X["login_hour"] > 23)).any():
        raise HTTPException(422, "login_hour must be between 0 and 23.")
    if (X[COUNT_FEATURES] < 0).any().any():
        raise HTTPException(422, "Count features cannot be negative.")
    if (X[COUNT_FEATURES] >= 2**63).any().any():
        raise HTTPException(422, "Count features are too large.")
    for col in BINARY_FEATURES:
        if not X[col].isin([0, 1]).all():
            raise HTTPException(422, f"{col} must contain only 0 or 1.")
    return X.astype(int)


def extract_labels(df: pd.DataFrame) -> np.ndarray | None:
    """Optional ground truth. Used ONLY for evaluation, never as a model input."""
    if LABEL_COLUMN not in df.columns:
        return None
    y = pd.to_numeric(df[LABEL_COLUMN], errors="coerce")
    if y.isna().any() or not y.isin([0, 1]).all():
        raise HTTPException(422, "label must contain only 0 or 1 when provided.")
    return y.to_numpy(dtype=int)
