import { useRef, useState } from "react";
import { downloadReport, fetchReport, type ReportOptions } from "../api";
import type { AppConfig } from "../types";

export default function ReportPanel({ scanId, config }: { scanId: string; config: AppConfig | null }) {
  const [opts, setOpts] = useState<ReportOptions>({ format: "md", top: 10, includeNotes: true, useLlm: false });
  const [text, setText] = useState("");
  const [llmUsed, setLlmUsed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const controller = useRef<AbortController | null>(null);

  async function run(fn: () => Promise<void>) {
    setBusy(true); setError(null);
    try { await fn(); } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }
  const o = { ...opts, top: Math.min(100, Math.max(1, opts.top || 1)) };

  async function preview() {
    const current = new AbortController();
    controller.current = current;
    setBusy(true); setGenerating(true); setError(null);
    try {
      const r = await fetchReport(scanId, o, current.signal);
      setText(r.text); setLlmUsed(r.llmUsed);
    } catch (e) {
      if ((e as Error).name !== "AbortError") setError((e as Error).message);
    } finally {
      if (controller.current === current) controller.current = null;
      setBusy(false); setGenerating(false);
    }
  }

  return (
    <section className="card">
      <h2>Incident report</h2>
      <p className="muted small">
        Generated from stored results: evidence, findings, uncertainty and recommended actions (for human approval).
        {config?.llm_available
          ? " When the optional summary is enabled, only aggregate counts and severity totals are sent to Gemini."
          : " The template report runs offline; no data leaves your machine."}
      </p>
      <div className="row filters">
        <label className="field"><span>Format</span>
          <select value={opts.format} onChange={(e) => setOpts({ ...opts, format: e.target.value as "md" | "txt" })}>
            <option value="md">Markdown (.md)</option><option value="txt">Plain text (.txt)</option></select></label>
        <label className="field"><span>Alerts detailed (1–100)</span>
          <input type="number" min={1} max={100} value={opts.top} onChange={(e) => setOpts({ ...opts, top: Number(e.target.value) })} /></label>
        <label><input type="checkbox" checked={opts.includeNotes} onChange={(e) => setOpts({ ...opts, includeNotes: e.target.checked })} /> Include analyst notes</label>
        <label title={config?.llm_available ? "" : "Configure SAD_LLM_ENABLED=1 and GEMINI_API_KEY on the backend to enable this option."}>
          <input type="checkbox" disabled={!config?.llm_available} checked={opts.useLlm}
            onChange={(e) => setOpts({ ...opts, useLlm: e.target.checked })} /> Optional LLM summary (aggregates only)
          {!config?.llm_available && <span className="muted small"> Unavailable: no LLM key configured. The offline template report is used.</span>}
        </label>
      </div>
      <div className="actions">
        <button disabled={busy} onClick={preview}>{generating ? "Generating…" : "Preview"}</button>
        {generating && <button className="secondary" onClick={() => controller.current?.abort()}>Cancel</button>}
        <button className="secondary" disabled={busy} onClick={() => run(() => downloadReport(scanId, o))}>Download</button>
      </div>
      {error && <div className="alert" role="alert">{error}</div>}
      {text && <>
        {opts.useLlm && <p className="muted small">{llmUsed ? "An LLM-written summary is included and labelled unverified." : "LLM summary could not be generated; showing the offline template report."}</p>}
        <pre className="report">{text}</pre>
      </>}
    </section>
  );
}
