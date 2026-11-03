import { useState, type RefObject } from "react";
import type { Mode } from "../types";

interface Props {
  loading: boolean;
  inputRef?: RefObject<HTMLInputElement>;
  onAnalyze: (file: File, mode: Mode, minHistory: number) => void;
  onSample: (mode: Mode, minHistory: number) => void;
}

export default function UploadForm({ loading, inputRef, onAnalyze, onSample }: Props) {
  const [file, setFile] = useState<File | null>(null);
  const [mode, setMode] = useState<Mode>("baseline");
  const [minHistory, setMinHistory] = useState(10);
  const mh = Math.min(100, Math.max(3, Math.round(minHistory) || 10));

  return (
    <section className="card row">
      <label className="field">
        <span>Login events CSV</span>
        <input ref={inputRef} type="file" accept=".csv,text/csv" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
        {file && <small className="muted">Selected: {file.name} ({(file.size / 1024).toFixed(1)} KB)</small>}
      </label>

      <label className="field">
        <span>Model mode</span>
        <select value={mode} onChange={(e) => setMode(e.target.value as Mode)}>
          <option value="baseline">Baseline model (versioned)</option>
          <option value="batch">Fit on this batch (relative scores)</option>
        </select>
      </label>

      <label className="field">
        <span>User-baseline min. history (3–100)</span>
        <input type="number" min={3} max={100} value={minHistory} onChange={(e) => setMinHistory(Number(e.target.value))} />
      </label>

      <div className="actions">
        <button disabled={!file || loading} onClick={() => file && onAnalyze(file, mode, mh)}>
          Analyze
        </button>
        <button className="secondary" disabled={loading} onClick={() => onSample(mode, mh)}>
          Try sample data
        </button>
      </div>
      <p className="muted small full">
        Required columns: failed_attempts, login_hour, unique_ips_24h, new_device, country_changed. Optional:
        label (0/1) for evaluation. Max 5 MB / 50,000 rows. No authentication: use non-sensitive data only.
      </p>
    </section>
  );
}
