from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

Status = Literal["new", "in_review", "escalated", "false_positive", "resolved"]
Severity = Literal["none", "low", "medium", "high", "critical"]


class ConfusionMatrix(BaseModel):
    tn: int
    fp: int
    fn: int
    tp: int


class Metrics(BaseModel):
    precision: float
    recall: float
    f1: float
    roc_auc: Optional[float] = None
    confusion_matrix: ConfusionMatrix


class Evaluation(BaseModel):
    positives: int
    model: Metrics
    rules: Metrics
    note: str


class HourBucket(BaseModel):
    hour: int
    total: int
    flagged: int


class AnalyzeResponse(BaseModel):
    """Original fields are unchanged; new fields are additive and optional."""
    scan_id: str
    created_at: str
    filename: str
    mode: str
    model_version: str
    threshold: float
    rows_analyzed: int
    anomalies_flagged: int
    anomaly_rate: float
    rule_flags: int
    hourly: list[HourBucket]
    evaluation: Optional[Evaluation] = None
    warning: str
    results: list[dict[str, Any]]
    # additive (v2)
    model_threshold: Optional[float] = None
    has_labels: bool = False
    uba_basis: Optional[str] = None
    uba_min_history: Optional[int] = None
    severity_counts: dict[str, int] = Field(default_factory=dict)


class ScanListItem(BaseModel):
    scan_id: str
    created_at: str
    filename: str
    rows_analyzed: int
    anomalies_flagged: int
    mode: Optional[str] = None
    model_version: Optional[str] = None
    threshold: Optional[float] = None
    has_labels: Optional[bool] = None


class HistoryPage(BaseModel):
    items: list[ScanListItem]
    total: int
    page: int
    page_size: int


# ---- thresholds
class ThresholdIn(BaseModel):
    threshold: float = Field(gt=0, lt=1)


class SweepPoint(BaseModel):
    threshold: float
    flagged: int
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1: Optional[float] = None


class Agreement(BaseModel):
    both: int
    model_only: int
    rules_only: int
    neither: int


class ThresholdEvaluation(BaseModel):
    scan_id: str
    threshold: float
    active_threshold: float
    model_threshold: float
    score_min: float
    score_max: float
    flagged: int
    flag_rate: float
    rule_flags: int
    evaluation: Optional[Evaluation] = None
    agreement: Agreement
    sweep: list[SweepPoint]
    suggestions: list[dict[str, float]]
    note: str


# ---- alerts
class Factor(BaseModel):
    factor: str
    points: int
    evidence: str


class Note(BaseModel):
    id: int
    author: str
    note: str
    created_at: str


class NoteIn(BaseModel):
    note: str = Field(min_length=1, max_length=2000)
    author: str = Field(default="analyst", min_length=1, max_length=64)


class StatusIn(BaseModel):
    status: Status


class AlertSummary(BaseModel):
    row: int
    anomaly_score: float
    flagged_by_model: bool
    rule_flag: bool
    severity: Severity
    points: int
    status: Status
    username: Optional[str] = None
    review_reason: str
    uba_status: str
    uba_deviations: int
    data: dict[str, Any]
    triage: Optional[float] = None
    triage_label: Optional[str] = None


class AlertPage(BaseModel):
    items: list[AlertSummary]
    total: int
    page: int
    page_size: int
    severity_counts: dict[str, int]
    status_counts: dict[str, int]


class AlertDetail(AlertSummary):
    threshold: float
    summary: str
    factors: list[Factor]
    context: dict[str, Any]
    steps: list[str]
    benign_possibilities: list[str]
    limitations: list[str]
    uba: dict[str, Any]
    notes: list[Note]
    status_updated_at: Optional[str] = None


# ---- users
class UserSummary(BaseModel):
    username: str
    events: int
    flagged: int
    max_score: float
    deviation_events: int


class UserPage(BaseModel):
    items: list[UserSummary]
    total: int
    page: int
    page_size: int
    uba_basis: str
    min_history: int


class UserProfile(BaseModel):
    username: str
    profile: dict[str, Any]
    min_history: int
    uba_basis: str
    notice: Optional[str] = None
    deviation_events: list[dict[str, Any]]


class AppConfig(BaseModel):
    llm_available: bool
    statuses: list[str]
    severity_policy: list[dict[str, str]]
    severity_bands: dict[str, str]
    limits: dict[str, int]
