import { useCallback, useEffect, useState } from "react";
import { addNote, getAlert, listAlerts, setStatus, type AlertQuery } from "../api";
import type { AlertDetail, AlertPage, AppConfig, Severity, Status } from "../types";
import { Pager, SeverityBadge, StatusBadge, TriageBadge, statusLabel } from "./Badges";

interface Props { scanId: string; config: AppConfig | null; refreshKey: number; initialUser?: string; onOpenUser: (u: string) => void }

export default function AlertsPanel({ scanId, config, refreshKey, initialUser = "", onOpenUser }: Props) {
  const [f, setF] = useState<AlertQuery>({ detector: "model", severity: "", status: "", username: initialUser, q: "", page: 1, pageSize: 15 });
  const [data, setData] = useState<AlertPage | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    listAlerts(scanId, f).then((d) => { setData(d); setError(null); }).catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [scanId, f]);
  useEffect(load, [load, refreshKey]);

  const set = (patch: Partial<AlertQuery>) => setF((p) => ({ ...p, ...patch, page: patch.page ?? 1 }));
  const emptyMessage = f.status
    ? `No alerts with status '${statusLabel(f.status).toLowerCase()}' yet. Open an alert and change its status, or set Status to All.`
    : "No alerts match these filters. Try setting Status to All or adjusting the other filters.";

  return (
    <div className="stack">
      <section className="card">
        <h2>Alerts</h2>
        <div className="row filters">
          <label className="field"><span>Detector</span>
            <select value={f.detector} onChange={(e) => set({ detector: e.target.value as AlertQuery["detector"] })}>
              <option value="model">Isolation Forest</option><option value="rules">Rule baseline</option><option value="either">Either</option>
            </select></label>
          <label className="field"><span>Severity</span>
            <select value={f.severity} onChange={(e) => set({ severity: e.target.value as Severity | "" })}>
              <option value="">All</option>{["critical", "high", "medium", "low", "none"].map((s) => <option key={s}>{s}</option>)}
            </select></label>
          <label className="field"><span>Status</span>
            <select value={f.status} onChange={(e) => set({ status: e.target.value as Status | "" })}>
              <option value="">All</option>{(config?.statuses ?? []).map((s) => <option key={s} value={s}>{statusLabel(s)}</option>)}
            </select></label>
          <label className="field"><span>Username (exact)</span>
            <input value={f.username} maxLength={100} onChange={(e) => set({ username: e.target.value })} /></label>
          <label className="field"><span>Search</span>
            <input type="search" value={f.q} maxLength={100} placeholder="IP, reason…" onChange={(e) => set({ q: e.target.value })} /></label>
        </div>
        {data && (
          <p className="muted small">
            Severity of matching alerts: {["critical", "high", "medium", "low"].map((s) => `${s} ${data.severity_counts[s] ?? 0}`).join(" · ")}
            {" | "}Status (all flagged): {Object.entries(data.status_counts).map(([k, v]) => `${statusLabel(k)} ${v}`).join(" · ") || "–"}
          </p>
        )}
        {error && <div className="alert" role="alert">{error}</div>}
        <div className="scroll">
          <table>
            <thead><tr><th>Row</th><th>Severity</th><th>Pts</th><th>Score</th><th>User</th><th>Status</th><th>UBA</th><th>Learned priority</th><th>Why (rules)</th></tr></thead>
            <tbody>
              {data?.items.map((a) => (
                <tr key={a.row} className={selected === a.row ? "selected" : ""}>
                  <td><button className="table-action" aria-label={`Open alert row ${a.row}`} onClick={() => setSelected(a.row)}>{a.row}</button></td>
                  <td><SeverityBadge severity={a.severity} /></td><td>{a.points}</td>
                  <td>{a.anomaly_score.toFixed(3)}</td><td>{a.username ?? "–"}</td><td><StatusBadge status={a.status} /></td>
                  <td>{a.uba_status === "ok" ? `${a.uba_deviations} dev.` : a.uba_status === "insufficient_history" ? "no history" : "–"}</td>
                  <td><TriageBadge value={a.triage} label={a.triage_label} /></td>
                  <td>{a.review_reason}</td>
                </tr>
              ))}
              {data && data.items.length === 0 && <tr><td colSpan={9} className="muted">{emptyMessage}</td></tr>}
            </tbody>
          </table>
        </div>
        {loading && <p className="muted small" role="status">Loading alerts…</p>}
        {data && <Pager page={data.page} total={data.total} pageSize={data.page_size} onPage={(p) => set({ page: p })} />}
      </section>
      {selected !== null && (
        <AlertDetailCard key={selected} scanId={scanId} row={selected} config={config} onClose={() => setSelected(null)}
          onChanged={load} onOpenUser={onOpenUser} />
      )}
    </div>
  );
}

function AlertDetailCard({ scanId, row, config, onClose, onChanged, onOpenUser }: {
  scanId: string; row: number; config: AppConfig | null; onClose: () => void; onChanged: () => void; onOpenUser: (u: string) => void;
}) {
  const [d, setD] = useState<AlertDetail | null>(null);
  const [note, setNote] = useState("");
  const [author, setAuthor] = useState("analyst");
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(() => {
    getAlert(scanId, row).then((x) => { setD(x); setError(null); }).catch((e: Error) => setError(e.message));
  }, [scanId, row]);
  useEffect(reload, [reload]);

  async function changeStatus(s: Status) {
    try { setD(await setStatus(scanId, row, s)); onChanged(); } catch (e) { setError((e as Error).message); }
  }
  async function submitNote() {
    if (!note.trim()) return;
    try { await addNote(scanId, row, note.trim(), author.trim() || "analyst"); setNote(""); reload(); } catch (e) { setError((e as Error).message); }
  }

  if (error) return <section className="card"><div className="alert" role="alert">{error}</div></section>;
  if (!d) return <section className="card muted">Loading alert…</section>;

  return (
    <section className="card">
      <div className="row between">
        <h2>Alert row {d.row} <SeverityBadge severity={d.severity} /> <span className="muted small">{d.points} points</span></h2>
        <button className="secondary" onClick={onClose}>Close</button>
      </div>
      <p>{d.summary}</p>
      {d.triage !== null && d.triage !== undefined && (
        <p className="small">Learned priority from analyst feedback: <TriageBadge value={d.triage} label={d.triage_label} /> <span className="muted">(estimated chance an analyst would escalate this; it never changes the alert's status)</span></p>
      )}

      <div className="grid2 tight">
        <div>
          <h3>Evidence from this event</h3>
          <ul className="evidence">{d.factors.map((f) => <li key={f.factor + f.evidence}><b>+{f.points}</b> {f.evidence}</li>)}
            {d.factors.length === 0 && <li className="muted">No signals recorded for this event.</li>}</ul>
          {Object.keys(d.context).length > 0 && (
            <p className="small muted">Context: {Object.entries(d.context).map(([k, v]) => `${k}=${String(v)}`).join(" · ")}</p>
          )}
          {d.username && <button className="secondary" onClick={() => onOpenUser(d.username!)}>Open user profile</button>}
          <h3>User baseline</h3>
          {d.uba.status === "ok" ? (
            d.uba.deviations.length ? <ul className="evidence">{d.uba.deviations.map((x) => <li key={x.detail}>{x.detail}</li>)}</ul>
              : <p className="muted small">Consistent with this user's {d.uba.n_prior} earlier events.</p>
          ) : <p className="muted small">{d.uba.status === "insufficient_history"
            ? `Insufficient history (${d.uba.n_prior} earlier events): no deviation is claimed.` : "No usable username in the file."}</p>}
        </div>
        <div>
          <h3>Suggested investigation steps</h3>
          <p className="small muted">Suggestions only. Remediation requires an authorised human; this tool takes no action.</p>
          <ol>{d.steps.map((s) => <li key={s}>{s}</li>)}</ol>
          <h3>Rule out benign explanations</h3>
          <ul>{d.benign_possibilities.map((s) => <li key={s}>{s}</li>)}</ul>
          <h3>Limitations</h3>
          <ul className="small muted">{d.limitations.map((s) => <li key={s}>{s}</li>)}</ul>
        </div>
      </div>

      <h3>Triage</h3>
      <div className="row filters">
        <label className="field"><span>Status</span>
          <select value={d.status} onChange={(e) => changeStatus(e.target.value as Status)}>
            {(config?.statuses ?? [d.status]).map((s) => <option key={s} value={s}>{statusLabel(s)}</option>)}
          </select></label>
        {d.status_updated_at && <span className="muted small">updated {d.status_updated_at}</span>}
      </div>
      <ul className="notes">{d.notes.map((n) => (
        <li key={n.id}><span className="muted small">{n.created_at} · {n.author}</span><br />{n.note}</li>
      ))}{d.notes.length === 0 && <li className="muted small">No notes yet.</li>}</ul>
      <div className="row">
        <label className="field grow"><span>Add note (plain text, max 2000 chars)</span>
          <textarea rows={2} maxLength={2000} value={note} onChange={(e) => setNote(e.target.value)} /></label>
        <label className="field"><span>Author</span>
          <input value={author} maxLength={64} onChange={(e) => setAuthor(e.target.value)} /></label>
        <button disabled={!note.trim()} onClick={submitNote}>Save note</button>
      </div>
    </section>
  );
}
