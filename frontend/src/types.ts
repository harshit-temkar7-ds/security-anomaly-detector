export type Mode = "baseline" | "batch";

export interface ConfusionMatrix { tn: number; fp: number; fn: number; tp: number }
export interface Metrics {
  precision: number;
  recall: number;
  f1: number;
  roc_auc: number | null;
  confusion_matrix: ConfusionMatrix;
}
export interface Evaluation { positives: number; model: Metrics; rules: Metrics; note: string }
export interface HourBucket { hour: number; total: number; flagged: number }

export interface EventRow {
  row: number;
  is_anomaly: boolean;
  anomaly_score: number;
  rule_flag: boolean;
  review_reason: string;
  [key: string]: string | number | boolean | null;
}

export interface AnalyzeResponse {
  scan_id: string;
  created_at: string;
  filename: string;
  mode: Mode;
  model_version: string;
  threshold: number;
  rows_analyzed: number;
  anomalies_flagged: number;
  anomaly_rate: number;
  rule_flags: number;
  hourly: HourBucket[];
  evaluation: Evaluation | null;
  warning: string;
  results: EventRow[];
  model_threshold?: number | null;
  has_labels?: boolean;
  uba_basis?: string | null;
  uba_min_history?: number | null;
  severity_counts?: Record<string, number>;
}

// ---------------------------------------------------------------- v2
export type Severity = "none" | "low" | "medium" | "high" | "critical";
export type Status = "new" | "in_review" | "escalated" | "false_positive" | "resolved";
export type Detector = "model" | "rules" | "either";

export interface AppConfig {
  llm_available: boolean;
  statuses: Status[];
  severity_policy: { factor: string; points: string; rule: string }[];
  severity_bands: Record<string, string>;
  limits: Record<string, number>;
}

export interface ScanListItem {
  scan_id: string;
  created_at: string;
  filename: string;
  rows_analyzed: number;
  anomalies_flagged: number;
  mode?: string | null;
  model_version?: string | null;
  threshold?: number | null;
  has_labels?: boolean | null;
}
export interface HistoryPage { items: ScanListItem[]; total: number; page: number; page_size: number }

export interface SweepPoint { threshold: number; flagged: number; precision: number | null; recall: number | null; f1: number | null }
export interface ThresholdEvaluation {
  scan_id: string;
  threshold: number;
  active_threshold: number;
  model_threshold: number;
  score_min: number;
  score_max: number;
  flagged: number;
  flag_rate: number;
  rule_flags: number;
  evaluation: Evaluation | null;
  agreement: { both: number; model_only: number; rules_only: number; neither: number };
  sweep: SweepPoint[];
  suggestions: { flag_rate: number; threshold: number }[];
  note: string;
}

export interface AlertSummary {
  row: number;
  anomaly_score: number;
  flagged_by_model: boolean;
  rule_flag: boolean;
  severity: Severity;
  points: number;
  status: Status;
  username: string | null;
  review_reason: string;
  uba_status: string;
  uba_deviations: number;
  data: Record<string, string | number | boolean | null>;
  triage?: number | null;
  triage_label?: string | null;
}
export interface AlertPage {
  items: AlertSummary[];
  total: number;
  page: number;
  page_size: number;
  severity_counts: Record<string, number>;
  status_counts: Record<string, number>;
}
export interface Factor { factor: string; points: number; evidence: string }
export interface NoteItem { id: number; author: string; note: string; created_at: string }
export interface UbaResult {
  status: string;
  n_prior: number;
  count: number;
  deviations: { feature: string; value: number; detail: string }[];
}
export interface AlertDetail extends AlertSummary {
  threshold: number;
  summary: string;
  factors: Factor[];
  context: Record<string, string | number | boolean | null>;
  steps: string[];
  benign_possibilities: string[];
  limitations: string[];
  uba: UbaResult;
  notes: NoteItem[];
  status_updated_at: string | null;
}

export interface UserSummary { username: string; events: number; flagged: number; max_score: number; deviation_events: number }
export interface UserPage { items: UserSummary[]; total: number; page: number; page_size: number; uba_basis: string; min_history: number }
export interface UserProfileData {
  username: string;
  profile: {
    events: number;
    sufficient_history: boolean;
    hour_histogram: number[];
    mean_failed_attempts: number;
    max_failed_attempts: number;
    mean_unique_ips_24h: number;
    new_device_rate: number;
    country_changed_rate: number;
    first_seen: string | null;
    last_seen: string | null;
  };
  min_history: number;
  uba_basis: string;
  notice: string | null;
  deviation_events: { row: number; anomaly_score: number; n_prior: number; deviations: { feature: string; detail: string }[] }[];
}

// ---- AI assist: plain-English search, copilot, analyst feedback ----
export interface NlSearchResult {
  query: string;
  interpreted: string[];
  understood: boolean;
  total: number;
  shown: number;
  items: AlertSummary[];
  note: string;
}
export interface CopilotAnswer {
  answer: string;
  engine: "gemini" | "offline";
  llm_reason: string;
  sources: number[];
  disclosure: string;
}
export interface TriageCv {
  folds: number;
  roc_auc: number;
  isolation_forest_score_alone_auc: number;
  benign_ranked_low: number;
  escalated_ranked_low: number;
  cutoff: number;
}
export interface TriageDriver { feature: string; weight: number; direction: string }
export interface FeedbackSummary {
  counts: { false_positive: number; escalated: number; resolved: number; in_review: number };
  min_per_class: number;
  still_needed: { false_positive: number; escalated: number };
  can_train: boolean;
  active: null | { version: string; created_at: string; trained_on: { false_positive: number; escalated: number }; cv: TriageCv; drivers: TriageDriver[] };
  has_previous: boolean;
  gate: { min_cv_auc: number; max_missed_escalation_rate: number; benign_cutoff: number };
  caveat: string;
}
export interface TrainResult {
  status: "ok" | "insufficient_feedback";
  activated: boolean;
  message?: string;
  passed_gate?: boolean;
  blocked_reasons?: string[];
  cv?: TriageCv;
  drivers?: TriageDriver[];
  version?: string;
  note?: string;
}
