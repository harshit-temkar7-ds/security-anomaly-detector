import { useCallback, useEffect, useRef, useState } from "react";
import { analyze, fetchSample, getConfig, getScan } from "./api";
import AlertsPanel from "./components/AlertsPanel";
import AnomalyChart from "./components/AnomalyChart";
import CopilotPanel from "./components/CopilotPanel";
import EvaluationPanel from "./components/EvaluationPanel";
import FeedbackPanel from "./components/FeedbackPanel";
import Hero from "./components/Hero";
import HistoryPanel from "./components/HistoryPanel";
import ReportPanel from "./components/ReportPanel";
import ResultsTable from "./components/ResultsTable";
import SummaryCards from "./components/SummaryCards";
import ThresholdPanel from "./components/ThresholdPanel";
import UploadForm from "./components/UploadForm";
import UsersPanel from "./components/UsersPanel";
import type { AnalyzeResponse, AppConfig, Mode } from "./types";

type Tab = "overview" | "alerts" | "copilot" | "model" | "users" | "feedback" | "report" | "history";
const NO_SCAN_NEEDED: Tab[] = ["history", "feedback"];
const TABS: [Tab, string][] = [["overview", "Overview"], ["alerts", "Alerts"], ["copilot", "AI Copilot"], ["model", "Model & threshold"],
  ["users", "Users"], ["feedback", "Feedback"], ["report", "Report"], ["history", "History"]];

export default function App() {
  const [data, setData] = useState<AnalyzeResponse | null>(null);
  const [config, setConfig] = useState<AppConfig | null>(null);
  const [tab, setTab] = useState<Tab>("overview");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [historyKey, setHistoryKey] = useState(0);
  const [alertsKey, setAlertsKey] = useState(0);
  const [selectedUser, setSelectedUser] = useState<string | null>(null);
  const [alertUser, setAlertUser] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => { getConfig().then(setConfig).catch(() => setConfig(null)); }, []);

  async function run(job: () => Promise<AnalyzeResponse>) {
    setLoading(true); setError(null);
    try {
      setData(await job()); setTab("overview"); setSelectedUser(null); setAlertUser("");
      setHistoryKey((k) => k + 1);
    } catch (e) {
      setData(null); setError(e instanceof Error ? e.message : "Unexpected error.");
    } finally { setLoading(false); }
  }

  // Reload the active scan after the threshold changes so every tab shows consistent flags.
  const refresh = useCallback(async () => {
    if (!data) return;
    try { setData(await getScan(data.scan_id)); setAlertsKey((k) => k + 1); setHistoryKey((k) => k + 1); }
    catch (e) { setError((e as Error).message); }
  }, [data]);

  const sev = data?.severity_counts ?? {};

  return (
    <main className="container">
      <Hero data={data}
        onUpload={() => {
          fileInputRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
          fileInputRef.current?.click();
        }}
        onSample={() => document.querySelector('input[type="file"]')?.closest("section")?.querySelector<HTMLButtonElement>("button.secondary")?.click()} />

      <UploadForm loading={loading} inputRef={fileInputRef}
        onAnalyze={(file, mode: Mode, mh) => run(() => analyze(file, mode, mh))}
        onSample={(mode: Mode, mh) => run(async () => analyze(await fetchSample(), mode, mh))} />

      {error && <div className="alert" role="alert">{error}</div>}
      {loading && <p className="muted">Analyzing…</p>}

      <nav className="tabs" aria-label="Sections">
        {TABS.map(([id, label]) => (
          <button key={id} className={tab === id ? "tab active" : "tab"} disabled={!NO_SCAN_NEEDED.includes(id) && !data}
            onClick={() => setTab(id)}>{label}</button>
        ))}
      </nav>

      {tab === "history" && (
        <HistoryPanel currentId={data?.scan_id ?? null} refreshKey={historyKey}
          onOpen={(id) => run(() => getScan(id))}
          onDeleted={(id) => { if (data?.scan_id === id) setData(null); }} />
      )}

      {!data && !NO_SCAN_NEEDED.includes(tab) && <p className="muted">Upload a CSV or try the sample data to begin. Previous scans are under History.</p>}

      {data && tab === "overview" && (<>
        <SummaryCards data={data} />
        <p className="muted small">
          Severity of flagged events:{" "}
          {["critical", "high", "medium", "low"].map((s) => (
            <span key={s} className={`badge sev-${s}`} style={{ marginRight: 6 }}>{s} {sev[s] ?? 0}</span>
          ))}
          · saved as scan <code>{data.scan_id}</code> with model <code>{data.model_version}</code>, threshold {data.threshold.toFixed(3)}
        </p>
        <div className="grid2">
          <AnomalyChart hourly={data.hourly} />
          {data.evaluation ? <EvaluationPanel evaluation={data.evaluation} /> : <NoLabels />}
        </div>
        <ResultsTable rows={data.results} scanId={data.scan_id} />
        <p className="muted small">{data.warning}</p>
      </>)}

      {data && tab === "alerts" && (
        <AlertsPanel key={`${data.scan_id}:${alertUser}`} scanId={data.scan_id} config={config} refreshKey={alertsKey}
          initialUser={alertUser} onOpenUser={(u) => { setSelectedUser(u); setTab("users"); }} />
      )}
      {data && tab === "copilot" && <CopilotPanel key={data.scan_id} scanId={data.scan_id} config={config} />}
      {tab === "feedback" && <FeedbackPanel onChanged={() => setAlertsKey((k) => k + 1)} />}
      {data && tab === "model" && <ThresholdPanel key={`${data.scan_id}:${data.threshold}`} scan={data} onApplied={refresh} />}
      {data && tab === "users" && (
        <UsersPanel scanId={data.scan_id} selectedUser={selectedUser} onSelect={setSelectedUser}
          onViewAlerts={(u) => { setAlertUser(u); setTab("alerts"); }} />
      )}
      {data && tab === "report" && <ReportPanel scanId={data.scan_id} config={config} />}
    </main>
  );
}

function NoLabels() {
  return (
    <section className="card">
      <h2>Evaluation</h2>
      <p className="muted">
        No <code>label</code> column (0/1) in this file, so precision and recall cannot be computed. Upload the
        labeled sample to compare the model with the rule baseline.
      </p>
    </section>
  );
}
