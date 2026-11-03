import type { Evaluation, Metrics } from "../types";

const pct = (n: number) => n.toFixed(3);

function Row({ name, m }: { name: string; m: Metrics }) {
  const c = m.confusion_matrix;
  return (
    <tr>
      <td>{name}</td>
      <td>{pct(m.precision)}</td>
      <td>{pct(m.recall)}</td>
      <td>{pct(m.f1)}</td>
      <td>{m.roc_auc === null ? "–" : pct(m.roc_auc)}</td>
      <td className="small">TP {c.tp} · FP {c.fp} · FN {c.fn} · TN {c.tn}</td>
    </tr>
  );
}

export default function EvaluationPanel({ evaluation }: { evaluation: Evaluation }) {
  return (
    <section className="card">
      <h2>Evaluation vs. labels ({evaluation.positives} positives)</h2>
      <div className="scroll">
        <table>
          <thead>
            <tr><th>Detector</th><th>Precision</th><th>Recall</th><th>F1</th><th>ROC AUC</th><th>Confusion</th></tr>
          </thead>
          <tbody>
            <Row name="Isolation Forest" m={evaluation.model} />
            <Row name="Rule baseline" m={evaluation.rules} />
          </tbody>
        </table>
      </div>
      <p className="muted small">{evaluation.note}</p>
    </section>
  );
}
