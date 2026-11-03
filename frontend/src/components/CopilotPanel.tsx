import { useRef, useState } from "react";
import { askCopilot, nlSearch } from "../api";
import type { AppConfig, CopilotAnswer, NlSearchResult } from "../types";
import { SeverityBadge, StatusBadge, TriageBadge } from "./Badges";

interface Props { scanId: string; config: AppConfig | null }
interface Msg { role: "user" | "bot"; text: string; meta?: CopilotAnswer }

const SEARCH_EXAMPLES = [
  "critical alerts at night with a new device",
  "more than 8 failed attempts",
  "new device and country changed",
  "unreviewed high alerts",
  "many ips top 10",
];
const ASK_EXAMPLES = [
  "Give me a summary of this scan",
  "What are the top alerts to review first?",
  "Which users look riskiest?",
  "How accurate is the model?",
  "Why so many alerts?",
];

export default function CopilotPanel({ scanId, config }: Props) {
  // ---- plain-English search ----
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<NlSearchResult | null>(null);
  const [searching, setSearching] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);

  async function runSearch(text: string) {
    if (!text.trim()) return;
    setQuery(text); setSearching(true); setSearchError(null);
    try { setResult(await nlSearch(scanId, text.trim())); }
    catch (e) { setSearchError((e as Error).message); setResult(null); }
    finally { setSearching(false); }
  }

  // ---- copilot chat ----
  const [msgs, setMsgs] = useState<Msg[]>([]);
  const [question, setQuestion] = useState("");
  const [asking, setAsking] = useState(false);
  const [askError, setAskError] = useState<string | null>(null);
  const [useLlm, setUseLlm] = useState(true);
  const end = useRef<HTMLDivElement>(null);
  const llmReady = !!config?.llm_available;

  async function ask(text: string) {
    const q = text.trim();
    if (!q || asking) return;
    setQuestion(""); setAsking(true); setAskError(null);
    setMsgs((m) => [...m, { role: "user", text: q }]);
    try {
      const a = await askCopilot(scanId, q, useLlm && llmReady);
      setMsgs((m) => [...m, { role: "bot", text: a.answer, meta: a }]);
    } catch (e) { setAskError((e as Error).message); }
    finally { setAsking(false); setTimeout(() => end.current?.scrollIntoView({ behavior: "smooth", block: "nearest" }), 50); }
  }

  return (
    <div className="stack">
      <section className="card">
        <h2>Search alerts in plain English</h2>
        <p className="muted small">
          A transparent parser turns your words into filters and shows exactly how it read them. It runs on this machine,
          searches flagged events only, and never guesses what it did not understand.
        </p>
        <div className="search-row">
          <input type="search" aria-label="Plain-English alert search" value={query} maxLength={300}
            placeholder="e.g. critical alerts at night with a new device"
            onChange={(e) => setQuery(e.target.value)} onKeyDown={(e) => e.key === "Enter" && runSearch(query)} />
          <button disabled={searching || !query.trim()} onClick={() => runSearch(query)}>{searching ? "Searching…" : "Search"}</button>
        </div>
        <div className="chips" aria-label="Example searches">
          {SEARCH_EXAMPLES.map((x) => <button key={x} className="chip" onClick={() => runSearch(x)}>{x}</button>)}
        </div>
        {searchError && <div className="alert" role="alert">{searchError}</div>}
        {result && (
          <>
            <p className="small">
              {result.understood
                ? <>Interpreted as: {result.interpreted.map((i) => <span className="chip" key={i} style={{ marginRight: 6 }}>{i}</span>)}</>
                : <span className="muted">I could not turn that into filters. Try words like severity (critical, high), night, new device, country changed, "more than 8 failed attempts", a user name, or a status.</span>}
            </p>
            {result.understood && (
              <p className="muted small">{result.total.toLocaleString()} matching alerts{result.total > result.shown ? `, showing the top ${result.shown}` : ""}. {result.note}</p>
            )}
            {result.understood && (
              <div className="scroll">
                <table>
                  <thead><tr><th>Row</th><th>Severity</th><th>Pts</th><th>User</th><th>Failed</th><th>Hour</th><th>IPs</th><th>New dev.</th><th>Country chg.</th><th>Status</th><th>Learned priority</th></tr></thead>
                  <tbody>
                    {result.items.map((a) => (
                      <tr key={a.row}>
                        <td>{a.row}</td><td><SeverityBadge severity={a.severity} /></td><td>{a.points}</td><td>{a.username ?? "–"}</td>
                        <td>{String(a.data.failed_attempts)}</td><td>{String(a.data.login_hour)}</td><td>{String(a.data.unique_ips_24h)}</td>
                        <td>{String(a.data.new_device)}</td><td>{String(a.data.country_changed)}</td>
                        <td><StatusBadge status={a.status} /></td><td><TriageBadge value={a.triage} label={a.triage_label} /></td>
                      </tr>
                    ))}
                    {result.items.length === 0 && <tr><td colSpan={11} className="muted">No flagged events match those filters.</td></tr>}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </section>

      <section className="card">
        <h2>Analyst copilot</h2>
        <p className="muted small">
          Ask questions about this scan. Answers come only from its stored data and cite alert rows. The copilot is read-only: it
          cannot change statuses, block accounts or take any action.{" "}
          {llmReady
            ? "Gemini is enabled: top-alert feature values and counts (no IPs, event ids or timestamps) are sent to answer. Tick the box to use the offline assistant instead."
            : "Gemini is not enabled, so answers come from the offline assistant and nothing leaves your machine."}
        </p>
        {llmReady && (
          <label><input type="checkbox" checked={useLlm} onChange={(e) => setUseLlm(e.target.checked)} /> Use Gemini for answers</label>
        )}
        <div className="chips" aria-label="Example questions">
          {ASK_EXAMPLES.map((x) => <button key={x} className="chip" disabled={asking} onClick={() => ask(x)}>{x}</button>)}
        </div>
        <div className="chat" role="log" aria-live="polite" aria-label="Copilot conversation">
          {msgs.length === 0 && <p className="muted small">No questions yet. Pick an example above or type your own below. Try "Explain alert row 12".</p>}
          {msgs.map((m, i) => (
            <div key={i} className={`msg ${m.role}`}>
              {m.text}
              {m.meta && (
                <span className="meta">
                  {m.meta.engine === "gemini" ? "Answered by Gemini from stored scan data" : "Answered by the offline assistant"}
                  {m.meta.llm_reason && m.meta.engine === "offline" && m.meta.llm_reason !== "disabled" ? ` (Gemini unavailable: ${m.meta.llm_reason})` : ""}
                  {m.meta.sources.length ? ` · rows cited: ${m.meta.sources.join(", ")}` : ""}
                  {" · "}{m.meta.disclosure}
                </span>
              )}
            </div>
          ))}
          {asking && <p className="muted small" role="status">Thinking…</p>}
          <div ref={end} />
        </div>
        {askError && <div className="alert" role="alert">{askError}</div>}
        <div className="search-row">
          <input aria-label="Ask the copilot" value={question} maxLength={500} placeholder="Ask about this scan…"
            onChange={(e) => setQuestion(e.target.value)} onKeyDown={(e) => e.key === "Enter" && ask(question)} />
          <button disabled={asking || !question.trim()} onClick={() => ask(question)}>Ask</button>
          {msgs.length > 0 && <button className="secondary" onClick={() => setMsgs([])}>Clear</button>}
        </div>
        <p className="muted small">Answers can be wrong. Verify against the Alerts tab before acting; flags are leads, not proof of an attack.</p>
      </section>
    </div>
  );
}
