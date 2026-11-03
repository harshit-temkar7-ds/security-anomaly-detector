import { useCallback, useEffect, useState } from "react";
import { getFeedback, rollbackFeedback, trainFeedback } from "../api";
import type { FeedbackSummary, TrainResult, TriageDriver } from "../types";

const pct = (x: number) => `${Math.round(x * 100)}%`;
const FEATURE_LABEL: Record<string, string> = {
  failed_attempts: "failed attempts", login_hour: "login hour", unique_ips_24h: "unique IPs (24h)",
  new_device: "new device", country_changed: "country changed", anomaly_score: "Isolation Forest score",
};

function Drivers({ items }: { items: TriageDriver[] }) {
  const max = Math.max(...items.map((d) => Math.abs(d.weight)), 0.001);
  return (
    <table>
      <thead><tr><th>Signal</th><th>Learned weight</th><th>Pushes</th></tr></thead>
      <tbody>
        {items.map((d) => (
          <tr key={d.feature}>
            <td>{FEATURE_LABEL[d.feature] ?? d.feature}</td>
            <td><div className="meter" aria-label={`weight ${d.weight}`}><span style={{ width: `${(Math.abs(d.weight) / max) * 100}%` }} /></div> <span className="muted small">{d.weight > 0 ? "+" : ""}{d.weight}</span></td>
            <td>{d.direction}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function FeedbackPanel({ onChanged }: { onChanged: () => void }) {
  const [s, setS] = useState<FeedbackSummary | null>(null);
  const [preview, setPreview] = useState<TrainResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(() => { getFeedback().then(setS).catch((e: Error) => setError(e.message)); }, []);
  useEffect(load, [load]);

  async function run(job: () => Promise<void>) {
    setBusy(true); setError(null); setNotice(null);
    try { await job(); load(); } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }
  const doPreview = () => run(async () => { setPreview(await trainFeedback(false)); });
  const doActivate = () => {
    if (!window.confirm("Activate this feedback model? Alerts will show a learned priority. You can roll back at any time.")) return;
    return run(async () => {
      const r = await trainFeedback(true);
      setPreview(r); setNotice(r.activated ? `Activated ${r.version}.` : r.message ?? "Not activated."); onChanged();
    });
  };
  const doRollback = () => {
    if (!window.confirm("Roll back to the previous feedback model (or switch learned priority off if there was none)?")) return;
    return run(async () => {
      const r = await rollbackFeedback();
      setNotice(r.status === "restored_previous" ? `Restored ${r.active_version}.` : r.status === "disabled" ? "Learned priority switched off." : "Nothing to roll back.");
      setPreview(null); onChanged();
    });
  };

  const a = s?.active;
  return (
    <div className="stack">
      <section className="card">
        <h2>Learn from analyst feedback</h2>
        <p className="muted small">
          The Isolation Forest cannot know what <i>your</i> analysts consider normal. This second stage learns from their decisions:
          alerts marked <b>false positive</b> count as benign, alerts marked <b>escalated</b> count as suspicious. It adds a
          <b> learned priority</b> to alerts to help humans rank them. It never closes, hides or blocks anything.
        </p>
        {error && <div className="alert" role="alert">{error}</div>}
        {notice && <p role="status" className="small">{notice}</p>}
        {s && (
          <>
            <div className="stats-strip" aria-label="Feedback counts" style={{ margin: "10px 0" }}>
              <div className="stat-cell"><strong>{s.counts.false_positive}</strong><span>False positives</span></div>
              <div className="stat-cell"><strong>{s.counts.escalated}</strong><span>Escalated</span></div>
              <div className="stat-cell"><strong>{s.min_per_class}</strong><span>Needed of each</span></div>
              <div className="stat-cell"><strong>{a ? "On" : "Off"}</strong><span>Learned priority</span></div>
            </div>
            {!s.can_train && (
              <p className="small">
                Not enough feedback yet: mark {s.still_needed.false_positive > 0 ? `${s.still_needed.false_positive} more false positive${s.still_needed.false_positive === 1 ? "" : "s"}` : ""}
                {s.still_needed.false_positive > 0 && s.still_needed.escalated > 0 ? " and " : ""}
                {s.still_needed.escalated > 0 ? `${s.still_needed.escalated} more escalated alert${s.still_needed.escalated === 1 ? "" : "s"}` : ""} in the Alerts tab (open an alert and change its status).
              </p>
            )}
            <div className="actions">
              <button disabled={busy || !s.can_train} onClick={doPreview}>{busy ? "Working…" : "Preview training"}</button>
              <button className="secondary" disabled={busy || !preview?.passed_gate || preview.activated} onClick={doActivate}>Activate</button>
              <button className="secondary" disabled={busy || (!a && !s.has_previous)} onClick={doRollback}>Roll back</button>
            </div>
            <p className="muted small">{s.caveat}</p>
          </>
        )}
      </section>

      {preview && preview.status === "insufficient_feedback" && (
        <section className="card"><p role="status">{preview.message}</p></section>
      )}
      {preview && preview.status === "ok" && preview.cv && (
        <section className="card">
          <h2>{preview.activated ? "Activated model" : "Training preview"}</h2>
          <p className={preview.passed_gate ? "small" : "small alert"} role="status">
            {preview.passed_gate
              ? "Passes the quality gate."
              : `Blocked: ${(preview.blocked_reasons ?? []).join("; ")}.`}
            {" "}Gate: cross-validated AUC at least {s ? s.gate.min_cv_auc : 0.75} and at most {s ? pct(s.gate.max_missed_escalation_rate) : "5%"} of escalated alerts ranked as likely benign.
          </p>
          <div className="scroll">
            <table>
              <thead><tr><th>Measure (out-of-fold, {preview.cv.folds} folds)</th><th>Value</th></tr></thead>
              <tbody>
                <tr><td>Learned model ROC-AUC (separating escalated from false positive)</td><td>{preview.cv.roc_auc}</td></tr>
                <tr><td>Isolation Forest score alone, same alerts</td><td>{preview.cv.isolation_forest_score_alone_auc}</td></tr>
                <tr><td>False positives ranked "likely benign" (priority below {pct(preview.cv.cutoff)})</td><td>{pct(preview.cv.benign_ranked_low)}</td></tr>
                <tr><td>Escalated alerts wrongly ranked "likely benign"</td><td>{pct(preview.cv.escalated_ranked_low)}</td></tr>
              </tbody>
            </table>
          </div>
          {preview.drivers && <><h3>What it learned (transparent weights)</h3><div className="scroll"><Drivers items={preview.drivers} /></div></>}
          <p className="muted small">{preview.note}</p>
        </section>
      )}

      {a && (
        <section className="card">
          <h2>Active model <span className="badge st-resolved">{a.version}</span></h2>
          <p className="small">Trained on {a.trained_on.false_positive} false positives and {a.trained_on.escalated} escalations. Cross-validated AUC {a.cv.roc_auc}. Trained {a.created_at} UTC.</p>
          <div className="scroll"><Drivers items={a.drivers} /></div>
          <p className="muted small">Re-run the preview after reviewing more alerts, then activate to refresh the model. Existing scans keep their stored scores; only the learned priority shown next to alerts changes.</p>
        </section>
      )}
    </div>
  );
}
