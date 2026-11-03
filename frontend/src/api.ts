import type {
  AlertDetail, AlertPage, AnalyzeResponse, AppConfig, CopilotAnswer, Detector, FeedbackSummary, HistoryPage, Mode,
  NlSearchResult, NoteItem, Severity, Status, ThresholdEvaluation, TrainResult, UserPage, UserProfileData,
} from "./types";

const BASE: string = import.meta.env.VITE_API_BASE ?? "/api";

function describeError(detail: unknown): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((x) => x?.msg ?? JSON.stringify(x)).join("; ");
  if (detail && typeof detail === "object") {
    const d = detail as { message?: string; missing?: string[] };
    if (d.message) return d.missing ? `${d.message}: ${d.missing.join(", ")}` : d.message;
  }
  return "Request failed.";
}

async function send(path: string, init?: RequestInit): Promise<Response> {
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, init);
  } catch {
    if (init?.signal?.aborted) throw new DOMException("Request cancelled.", "AbortError");
    throw new Error("Cannot reach the API. Is the backend running, and does the proxy port in frontend/vite.config.ts match it (default 8001)?");
  }
  if (!res.ok) {
    const payload = await res.json().catch(() => ({}));
    const detail = (payload as { detail?: unknown }).detail;
    if (res.status === 404 && detail === "Not Found") {
      // FastAPI's own "no such route" reply. The app's real 404s use specific messages ("Scan not found.").
      throw new Error(
        "The backend you are connected to does not have this feature. An older backend is probably still running, " +
        "or the proxy in frontend/vite.config.ts points at the wrong port. Stop all backends, start this project's " +
        "backend, then restart npm run dev (see README: Troubleshooting).",
      );
    }
    throw new Error(describeError(detail));
  }
  return res;
}

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  return (await send(path, init)).json() as Promise<T>;
}

const body = (method: string, data: unknown): RequestInit => ({
  method,
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(data),
});

function qs(params: Record<string, string | number | boolean | undefined | null>): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") q.set(k, String(v));
  const s = q.toString();
  return s ? `?${s}` : "";
}

export async function analyze(file: File, mode: Mode, ubaMinHistory?: number): Promise<AnalyzeResponse> {
  const form = new FormData();
  form.append("file", file);
  return json<AnalyzeResponse>(`/analyze${qs({ mode, uba_min_history: ubaMinHistory })}`, { method: "POST", body: form });
}

export async function fetchSample(): Promise<File> {
  const res = await fetch("/sample_login_events.csv");
  if (!res.ok) throw new Error("Sample file not found.");
  return new File([await res.blob()], "sample_login_events.csv", { type: "text/csv" });
}

export const getConfig = () => json<AppConfig>("/config");
export const getScan = (id: string) => json<AnalyzeResponse>(`/scans/${id}`);
export const listHistory = (page: number, pageSize: number, q: string) =>
  json<HistoryPage>(`/history${qs({ page, page_size: pageSize, q })}`);
export const deleteScan = async (id: string) => { await send(`/scans/${id}`, { method: "DELETE" }); };

export const evaluateThreshold = (id: string, threshold: number) =>
  json<ThresholdEvaluation>(`/scans/${id}/evaluate${qs({ threshold })}`);
export const applyThreshold = (id: string, threshold: number) =>
  json<ThresholdEvaluation>(`/scans/${id}/threshold`, body("PUT", { threshold }));

export interface AlertQuery {
  detector: Detector; severity: Severity | ""; status: Status | ""; username: string; q: string;
  page: number; pageSize: number;
}
export const listAlerts = (id: string, f: AlertQuery) =>
  json<AlertPage>(`/scans/${id}/alerts${qs({
    detector: f.detector, severity: f.severity, status: f.status, username: f.username, q: f.q,
    page: f.page, page_size: f.pageSize,
  })}`);
export const getAlert = (id: string, row: number) => json<AlertDetail>(`/scans/${id}/alerts/${row}`);
export const setStatus = (id: string, row: number, status: Status) =>
  json<AlertDetail>(`/scans/${id}/alerts/${row}`, body("PATCH", { status }));
export const addNote = (id: string, row: number, note: string, author: string) =>
  json<NoteItem>(`/scans/${id}/alerts/${row}/notes`, body("POST", { note, author }));

export const listUsers = (id: string, q: string, page: number, pageSize: number) =>
  json<UserPage>(`/scans/${id}/users${qs({ q, page, page_size: pageSize })}`);
export const getUserProfile = (id: string, username: string) =>
  json<UserProfileData>(`/scans/${id}/user-profile${qs({ username })}`);

export interface ReportOptions { format: "md" | "txt"; top: number; includeNotes: boolean; useLlm: boolean; row?: number }
const reportQuery = (o: ReportOptions, download: boolean) =>
  qs({ format: o.format, top: o.top, include_notes: o.includeNotes, use_llm: o.useLlm, row: o.row, download });
export async function fetchReport(id: string, o: ReportOptions, signal?: AbortSignal): Promise<{ text: string; llmUsed: boolean; llmReason: string }> {
  const res = await send(`/scans/${id}/report${reportQuery(o, false)}`, { signal });
  return { text: await res.text(), llmUsed: res.headers.get("X-LLM-Used") === "true",
    llmReason: res.headers.get("X-LLM-Reason") ?? "network" };
}
export async function downloadReport(id: string, o: ReportOptions): Promise<void> {
  const res = await send(`/scans/${id}/report${reportQuery(o, true)}`);
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = `incident_report_${id}.${o.format}`;
  a.click();
  URL.revokeObjectURL(url);
}

// ---- AI assist ----
export const nlSearch = (id: string, query: string) =>
  json<NlSearchResult>(`/scans/${id}/nl-search`, body("POST", { query }));
export const askCopilot = (id: string, question: string, useLlm: boolean) =>
  json<CopilotAnswer>(`/scans/${id}/copilot`, body("POST", { question, use_llm: useLlm }));
export const getFeedback = () => json<FeedbackSummary>("/feedback/summary");
export const trainFeedback = (activate: boolean) => json<TrainResult>("/feedback/train", body("POST", { activate }));
export const rollbackFeedback = () => json<{ status: string; active_version: string | null }>("/feedback/rollback", body("POST", {}));
