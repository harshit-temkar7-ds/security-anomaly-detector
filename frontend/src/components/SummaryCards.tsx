import type { AnalyzeResponse } from "../types";

export default function SummaryCards({ data }: { data: AnalyzeResponse }) {
  const items = [
    ["Rows analyzed", data.rows_analyzed.toLocaleString()],
    ["Anomalies flagged", data.anomalies_flagged.toLocaleString()],
    ["Flag rate", `${(data.anomaly_rate * 100).toFixed(1)}%`],
    ["Rule-baseline flags", data.rule_flags.toLocaleString()],
    ["Model", data.model_version],
  ];
  return (
    <section className="cards">
      {items.map(([label, value]) => (
        <div className="card kpi" key={label}>
          <div className="kpi-value">{value}</div>
          <div className="muted small">{label}</div>
        </div>
      ))}
    </section>
  );
}
