import { useCallback, useEffect, useState } from "react";
import { deleteScan, listHistory } from "../api";
import type { HistoryPage } from "../types";
import { Pager } from "./Badges";

interface Props { currentId: string | null; onOpen: (id: string) => void; onDeleted: (id: string) => void; refreshKey: number }

export default function HistoryPanel({ currentId, onOpen, onDeleted, refreshKey }: Props) {
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const [data, setData] = useState<HistoryPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    listHistory(page, 8, q).then((d) => { setData(d); setError(null); }).catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [page, q]);
  useEffect(load, [load, refreshKey]);

  async function remove(id: string, name: string) {
    if (!window.confirm(`Delete scan "${name}" and all its alerts and notes? This cannot be undone.`)) return;
    try { await deleteScan(id); onDeleted(id); load(); } catch (e) { setError((e as Error).message); }
  }

  return (
    <section className="card">
      <h2>Scan history</h2>
      <p className="muted small">Scans are stored in a local SQLite database, including model version, threshold, results, alert status and notes.</p>
      <input type="search" aria-label="Search file name" placeholder="Search file name…" value={q} maxLength={100} onChange={(e) => { setQ(e.target.value); setPage(1); }} />
      {error && <div className="alert" role="alert">{error}</div>}
      {loading && <p className="muted small" role="status">Loading scan history…</p>}
      <div className="scroll"><table>
        <thead><tr><th>When (UTC)</th><th>File</th><th>Rows</th><th>Flagged</th><th>Threshold</th><th>Model</th><th>Labels</th><th /></tr></thead>
        <tbody>
          {data?.items.map((s) => (
            <tr key={s.scan_id} className={s.scan_id === currentId ? "selected" : undefined}>
              <td>{s.created_at.replace("T", " ").slice(0, 19)}</td><td>{s.filename}</td><td>{s.rows_analyzed.toLocaleString()}</td>
              <td>{s.anomalies_flagged.toLocaleString()}</td><td>{s.threshold?.toFixed(3) ?? "–"}</td>
              <td className="small">{s.model_version ?? "–"} {s.mode ? `(${s.mode})` : ""}</td><td>{s.has_labels ? "yes" : "no"}</td>
              <td className="actions"><button className="secondary" onClick={() => onOpen(s.scan_id)}>Open</button>
                <button className="secondary danger" onClick={() => remove(s.scan_id, s.filename)}>Delete</button></td>
            </tr>
          ))}
          {data && data.items.length === 0 && <tr><td colSpan={8} className="muted">No saved scans yet.</td></tr>}
        </tbody>
      </table></div>
      {data && <Pager page={data.page} total={data.total} pageSize={data.page_size} onPage={setPage} />}
    </section>
  );
}
