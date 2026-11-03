import { useMemo, useState } from "react";
import { downloadCsv, toCsv } from "../csv";
import type { EventRow } from "../types";

const PAGE_SIZE = 25;
const PREFERRED = ["row", "event_id", "timestamp", "username", "source_ip", "failed_attempts", "login_hour",
  "unique_ips_24h", "new_device", "country_changed"];
const TAIL = ["anomaly_score", "is_anomaly", "rule_flag", "review_reason"];

export default function ResultsTable({ rows, scanId }: { rows: EventRow[]; scanId: string }) {
  const [onlyFlagged, setOnlyFlagged] = useState(true);
  const [query, setQuery] = useState("");
  const [minScore, setMinScore] = useState(0);
  const [page, setPage] = useState(0);

  const columns = useMemo(() => {
    const present = new Set(Object.keys(rows[0] ?? {}));
    const head = PREFERRED.filter((c) => present.has(c));
    const extra = [...present].filter((c) => !PREFERRED.includes(c) && !TAIL.includes(c));
    return [...head, ...extra, ...TAIL];
  }, [rows]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return rows.filter(
      (r) =>
        (!onlyFlagged || r.is_anomaly) &&
        r.anomaly_score >= minScore &&
        (!q || Object.values(r).some((v) => String(v ?? "").toLowerCase().includes(q))),
    );
  }, [rows, onlyFlagged, query, minScore]);

  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(page, pages - 1);
  const visible = filtered.slice(safePage * PAGE_SIZE, (safePage + 1) * PAGE_SIZE);
  const reset = () => setPage(0);

  return (
    <section className="card">
      <div className="row between">
        <h2>Events ({filtered.length.toLocaleString()})</h2>
        <button className="secondary" onClick={() => downloadCsv(`scan_${scanId}.csv`, toCsv(filtered, columns))}>
          Export filtered CSV
        </button>
      </div>

      <div className="row filters">
        <label><input type="checkbox" checked={onlyFlagged} onChange={(e) => { setOnlyFlagged(e.target.checked); reset(); }} /> Flagged only</label>
        <label>Min score <input type="number" step="0.01" min={0} max={1} value={minScore} onChange={(e) => { setMinScore(Number(e.target.value) || 0); reset(); }} /></label>
        <input type="search" placeholder="Search user, IP, reason…" value={query} onChange={(e) => { setQuery(e.target.value); reset(); }} />
      </div>

      <div className="scroll">
        <table>
          <thead><tr>{columns.map((c) => <th key={c}>{c}</th>)}</tr></thead>
          <tbody>
            {visible.map((r) => (
              <tr key={r.row} className={r.is_anomaly ? "flagged" : undefined}>
                {columns.map((c) => <td key={c}>{format(r[c])}</td>)}
              </tr>
            ))}
            {visible.length === 0 && <tr><td colSpan={columns.length} className="muted">No matching events.</td></tr>}
          </tbody>
        </table>
      </div>

      <div className="row between">
        <span className="muted small">Page {safePage + 1} of {pages}</span>
        <span className="actions">
          <button className="secondary" disabled={safePage === 0} onClick={() => setPage(safePage - 1)}>Prev</button>
          <button className="secondary" disabled={safePage >= pages - 1} onClick={() => setPage(safePage + 1)}>Next</button>
        </span>
      </div>
    </section>
  );
}

function format(v: string | number | boolean | null | undefined): string {
  if (v === null || v === undefined) return "";
  if (typeof v === "boolean") return v ? "yes" : "no";
  if (typeof v === "number" && !Number.isInteger(v)) return v.toFixed(4);
  return String(v);
}
