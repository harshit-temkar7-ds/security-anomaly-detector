import type { Severity, Status } from "../types";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge sev-${severity}`}>{severity}</span>;
}
export const statusLabel = (s: Status | string) => s.replace("_", " ");
export function StatusBadge({ status }: { status: Status }) {
  return <span className={`badge st-${status}`}>{statusLabel(status)}</span>;
}
export function Pager({ page, total, pageSize, onPage }: { page: number; total: number; pageSize: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <div className="row between">
      <span className="muted small">Page {page} of {pages} · {total.toLocaleString()} items</span>
      <span className="actions">
        <button className="secondary" disabled={page <= 1} onClick={() => onPage(page - 1)}>Prev</button>
        <button className="secondary" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</button>
      </span>
    </div>
  );
}

export function TriageBadge({ value, label }: { value?: number | null; label?: string | null }) {
  if (value === null || value === undefined) return <span className="muted">–</span>;
  const cls = label === "likely benign" ? "tri-benign" : label === "likely suspicious" ? "tri-sus" : "tri-unsure";
  return <span className={`badge ${cls}`} title="Learned from analyst decisions. A ranking aid, never an automatic decision.">{Math.round(value * 100)}% · {label}</span>;
}
