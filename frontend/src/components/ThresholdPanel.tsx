import { useEffect, useRef, useState } from "react";
import { CartesianGrid, Legend, Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { applyThreshold, evaluateThreshold } from "../api";
import type { AnalyzeResponse, Metrics, ThresholdEvaluation } from "../types";

interface Props { scan: AnalyzeResponse; onApplied: () => void }
const fmt = (n: number | null | undefined) => (n === null || n === undefined ? "–" : n.toFixed(3));

function MetricRow({ name, m }: { name: string; m: Metrics }) {
  const c = m.confusion_matrix;
  return (
    <tr><td>{name}</td><td>{fmt(m.precision)}</td><td>{fmt(m.recall)}</td><td>{fmt(m.f1)}</td><td>{fmt(m.roc_auc)}</td>
      <td className="small">TP {c.tp} · FP {c.fp} · FN {c.fn} · TN {c.tn}</td></tr>
  );
}

export default function ThresholdPanel({ scan, onApplied }: Props) {
  const [thr, setThr] = useState(scan.threshold);
  const [ev, setEv] = useState<ThresholdEvaluation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [previewing, setPreviewing] = useState(true);
  const reqId = useRef(0);

  // Debounced preview; stale responses are ignored.
  useEffect(() => {
    const id = ++reqId.current;
    setPreviewing(true);
    const t = setTimeout(() => {
      evaluateThreshold(scan.scan_id, Math.min(0.999, Math.max(0.001, thr)))
        .then((r) => { if (id === reqId.current) { setEv(r); setError(null); setPreviewing(false); } })
        .catch((e: Error) => { if (id === reqId.current) { setError(e.message); setPreviewing(false); } });
    }, 250);
    return () => clearTimeout(t);
  }, [thr, scan.scan_id, scan.threshold]);

  async function apply(value: number) {
    setBusy(true);
    try { await applyThreshold(scan.scan_id, value); setThr(value); onApplied(); } catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  }

  const lo = ev?.score_min ?? 0.3, hi = ev?.score_max ?? 0.9;
  const labelled = !!ev?.evaluation;
  const dirty = ev ? Math.abs(thr - ev.active_threshold) > 1e-6 : false;

  return (
    <div className="stack">
      <section className="card">
        <h2>Model threshold</h2>
        <p className="muted small">
          Events with an anomaly score at or above the threshold are flagged. The score is a relative ranking, not a probability.
          Active threshold: <b>{scan.threshold.toFixed(4)}</b> · model default: <b>{(scan.model_threshold ?? scan.threshold).toFixed(4)}</b>.
        </p>
        <div className="row filters">
          <input className="slider" type="range" min={lo} max={hi} step={0.001} value={Math.min(hi, Math.max(lo, thr))}
            onChange={(e) => setThr(Number(e.target.value))} aria-label="Threshold" />
          <input type="number" step={0.001} min={0.001} max={0.999} value={Number(thr.toFixed(4))}
            onChange={(e) => setThr(Number(e.target.value) || 0)} aria-label="Threshold value" />
          <button disabled={busy || !dirty} onClick={() => apply(thr)}>Apply to this scan</button>
          <button className="secondary" disabled={busy} onClick={() => apply(scan.model_threshold ?? scan.threshold)}>Reset to model default</button>
        </div>
        <div className="row filters">
          <span className="muted small">Label-free presets (flag the top share of this scan):</span>
          {ev?.suggestions.map((s) => (
            <button key={s.flag_rate} className="secondary" onClick={() => setThr(s.threshold)}>{(s.flag_rate * 100).toFixed(0)}% → {s.threshold.toFixed(3)}</button>
          ))}
        </div>
        {error && <div className="alert" role="alert">{error}</div>}
        {previewing && <p className="muted small" role="status">Updating threshold preview…</p>}
        {!previewing && !error && !ev && <p className="muted small">No threshold preview is available for this scan.</p>}
        {ev && (
          <div className="cards">
            <div className="card kpi"><div className="kpi-value">{ev.flagged.toLocaleString()}</div><div className="muted small">flagged at {ev.threshold.toFixed(3)} ({(ev.flag_rate * 100).toFixed(1)}%)</div></div>
            <div className="card kpi"><div className="kpi-value">{ev.rule_flags.toLocaleString()}</div><div className="muted small">rule-baseline flags</div></div>
            <div className="card kpi"><div className="kpi-value">{ev.agreement.both}</div><div className="muted small">flagged by both</div></div>
            <div className="card kpi"><div className="kpi-value">{ev.agreement.model_only} / {ev.agreement.rules_only}</div><div className="muted small">model only / rules only</div></div>
          </div>
        )}
      </section>

      <div className="grid2">
        <section className="card">
          <h2>Isolation Forest vs rule baseline</h2>
          {ev?.evaluation ? (
            <div className="scroll"><table>
              <thead><tr><th>Detector</th><th>Precision</th><th>Recall</th><th>F1</th><th>ROC AUC</th><th>Confusion</th></tr></thead>
              <tbody><MetricRow name="Isolation Forest" m={ev.evaluation.model} /><MetricRow name="Rule baseline" m={ev.evaluation.rules} /></tbody>
            </table></div>
          ) : <p className="muted">No <code>label</code> column in this scan, so precision/recall are unavailable. The agreement counts above still compare the two detectors.</p>}
          <p className="muted small">{ev?.note}</p>
        </section>

        <section className="card">
          <h2>{labelled ? "Metrics across thresholds" : "Flagged events across thresholds"}</h2>
          <div style={{ width: "100%", height: 280 }}>
            <ResponsiveContainer>
              <LineChart data={ev?.sweep ?? []} margin={{ top: 8, right: 12, left: -8, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" opacity={0.3} />
                <XAxis dataKey="threshold" type="number" domain={["dataMin", "dataMax"]} tick={{ fontSize: 11 }} tickFormatter={(v: number) => v.toFixed(2)} />
                <YAxis tick={{ fontSize: 11 }} domain={labelled ? [0, 1] : [0, "auto"]} />
                <Tooltip />
                <Legend />
                {labelled ? (<>
                  <Line type="monotone" dataKey="precision" stroke="#2f9e44" dot={false} />
                  <Line type="monotone" dataKey="recall" stroke="#d64545" dot={false} />
                  <Line type="monotone" dataKey="f1" stroke="#2459d6" dot={false} />
                </>) : <Line type="monotone" dataKey="flagged" stroke="#2459d6" dot={false} />}
                <ReferenceLine x={thr} stroke="#888" strokeDasharray="4 4" />
              </LineChart>
            </ResponsiveContainer>
          </div>
          {labelled && <p className="muted small">Diagnostic view only. Picking the "best" threshold on the same labels and reporting it would leak the labels and overstate performance. Choose thresholds by analyst capacity (flag rate).</p>}
        </section>
      </div>
    </div>
  );
}
