import type { AnalyzeResponse } from "../types";

interface Props {
  data: AnalyzeResponse | null;
  onSample: () => void;
  onUpload: () => void;
}

export default function Hero({ data, onSample, onUpload }: Props) {
  const stats: [string, string][] = data
    ? [
        ["Events analyzed", data.rows_analyzed.toLocaleString()],
        ["Flagged", data.anomalies_flagged.toLocaleString()],
        ["Flag rate", `${(data.anomaly_rate * 100).toFixed(1)}%`],
        ["Rule-baseline flags", data.rule_flags.toLocaleString()],
      ]
    : [["Detectors compared", "2"], ["Behaviour signals", "5"], ["Login-hour view", "24h"], ["Automatic actions", "0"]];

  return (
    <>
      <header className="site-header">
        <a className="brand" href="#top" aria-label="LogGuard home">
          <svg viewBox="0 0 40 40" aria-hidden="true"><path d="M20 3 34 9v10c0 9-5.7 14.4-14 18C11.7 33.4 6 28 6 19V9l14-6Z"/><path d="m13 20 4.5 4.5L27 15"/></svg>
          <span>LogGuard</span>
        </a>
        <nav className="top-nav" aria-label="Product sections"><span>SECURITY ANALYTICS</span><span>HUMAN LED REVIEW</span><span>ANOMALY DETECTION</span></nav>
      </header>

      <section className="hero" id="top">
        <div className="hero-copy">
          <div className="eyebrow"><span className="eyebrow-dot" /> SECURITY EVENT ANALYSIS</div>
          <h1>See the signal.<br />Protect what <span className="gradient-text">matters.</span></h1>
          <p className="hero-description">Explore unusual login activity with clear, human-reviewable signals. Flags are leads for an analyst, not proof of an attack.</p>
          <div className="hero-actions">
            <button onClick={onSample}>Try sample data <span aria-hidden="true">↗</span></button>
            <button className="secondary" onClick={onUpload}>Upload CSV</button>
          </div>
          <p className="hero-note">Scores are not probabilities. LogGuard never takes remediation actions.</p>
        </div>
        <div className="hero-art" aria-hidden="true">
          <svg viewBox="0 0 440 360" role="img">
            <defs>
              <linearGradient id="shieldStroke" x1="70" y1="45" x2="340" y2="310" gradientUnits="userSpaceOnUse"><stop stopColor="#22d3ee"/><stop offset=".52" stopColor="#3b82f6"/><stop offset="1" stopColor="#a855f7"/></linearGradient>
              <radialGradient id="shieldGlow"><stop stopColor="#2563eb" stopOpacity=".3"/><stop offset="1" stopColor="#2563eb" stopOpacity="0"/></radialGradient>
              <filter id="neon"><feGaussianBlur stdDeviation="7" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
            </defs>
            <ellipse cx="220" cy="186" rx="196" ry="168" fill="url(#shieldGlow)"/>
            <path className="ring ring-one" d="M220 17 384 112v136l-164 95L56 248V112L220 17Z" />
            <path className="ring ring-two" d="M220 47 354 125v110l-134 78L86 235V125L220 47Z" />
            <circle className="orbit orbit-a" cx="84" cy="94" r="4"/><circle className="orbit orbit-b" cx="354" cy="261" r="4"/>
            <path className="shield" d="M220 77 298 109v62c0 58-31 93-78 115-47-22-78-57-78-115v-62l78-32Z" />
            <path className="keyhole" d="M220 143a23 23 0 1 0 0 46 23 23 0 0 0 0-46Zm-10 42h20l5 35h-30l5-35Z" />
            <path className="spark" d="m329 83 4 11 11 4-11 4-4 11-4-11-11-4 11-4 4-11Z"/>
          </svg>
        </div>
      </section>

      <section className="stats-strip" aria-label="Analysis summary">
        {stats.map(([label, value]) => <div className="stat-cell" key={label}><strong>{value}</strong><span>{label}</span></div>)}
      </section>
    </>
  );
}
