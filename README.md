# Security Log Anomaly Detector

An educational, end-to-end ML project: upload a CSV of login events, flag unusual ones with an
**Isolation Forest**, compare against a **transparent rule baseline**, then **investigate** alerts
(evidence, severity, status, notes), review **per-user behaviour**, tune the **threshold**, keep a
persistent **SQLite scan history**, and export **incident reports**, all in a React dashboard.
Built as preparation for an AI internship at a cybersecurity company.

## What's new in v2

| Feature | Summary |
|---|---|
| **Alert investigation** | Transparent points-based severity (low/medium/high/critical), evidence quoted from the event's own fields, suggested investigation steps, status workflow and analyst notes. Nothing is invented; remediation stays with humans. |
| **Adjustable threshold** | Slider + presets, live flagged counts and metrics, Isolation Forest vs rule baseline, agreement counts. Thresholds are chosen label-free; labels are only used to report metrics. |
| **SQLite history** | Scans, model version, threshold, per-event results, status and notes persist across restarts; paginated history, reopen, delete. |
| **User behaviour analytics** | Per-user baselines from each user's *earlier* events only (no future leakage), explained deviations, explicit "insufficient history" handling. |
| **Incident reports** | Offline template report (Markdown or text) with evidence, findings, uncertainty and recommended actions. Optional, off-by-default LLM summary. |

> **Scope:** synthetic/fictional data only. This is a learning project, not a production security
> product, and makes no claims about any company's internal systems. Anomaly flags are leads for a
> human analyst, not proof of an attack.

## What's new in v3: AI-assist layer

| Feature | What it does | Needs a key? |
|---|---|---|
| **Plain-English search** | Type "critical alerts at night with a new device" and a transparent parser turns it into visible filters. Anything it does not understand is reported, never guessed. | No (offline) |
| **Analyst copilot** | Ask "summarise this scan", "which users look riskiest?", "explain alert row 12". Answers come only from stored scan data and cite rows. Read-only: it cannot change statuses or take action. | No. Offline assistant by default; Gemini is optional |
| **Learning from analyst feedback** | Alerts marked *false positive* (benign) or *escalated* (suspicious) train a transparent logistic-regression triage model. It adds a **learned priority** to alerts. Cross-validated, quality-gated, versioned, with one-click rollback. It never closes or hides alerts. | No |

Design rules for the AI layer: the AI explains and ranks, a human decides; answers are grounded in stored data;
every AI feature works offline; Gemini is opt-in and receives the minimum data (see *Key design decisions*).

## Using real-derived data: the RBA login dataset

Dataset: Wiefling, Jorgensen, Thunem, Lo Iacono, *Login Data Set for Risk-Based Authentication*
(Zenodo, DOI 10.5281/zenodo.6782155). It is **derived from real login behaviour** at a large online service (33M+
logins, 3.3M users, labelled account takeovers and attack IPs), but its IPs, user agents, timestamps and RTTs were
**generated for privacy**. Describe it as "derived from real-world login behaviour", not "raw production logs", and cite
the authors.

The raw file (~8 GB) is far over the dashboard limit (5 MB / 50,000 rows) and has a different schema, so import it first:

```powershell
cd backend
python -m scripts.import_rba "C:\path\to\rba-dataset.csv" --out ..\data\rba_sample.csv
```

It streams the file in two passes (a few minutes, well under 1 GB of RAM), keeps **every** account-takeover user, a random
set of attack-IP users and a random set of normal users with their full histories, and computes the five model features
from each user's earlier events only. Then upload `data/rba_sample.csv`, choose **Model mode = Batch** (the built-in
baseline was trained on synthetic data and does not fit this data) and click **Analyze**.

| Option | Default | Meaning |
|---|---|---|
| `--label` | `either` | `takeover` (hardest, very few positives), `attack_ip`, or `either` |
| `--max-rows` | 30000 | sample size (limit 50,000 rows / 5 MB) |
| `--positive-rate` | 0.03 | max share of positive events kept, so attacks stay rare |
| `--min-events` / `--max-events` | 5 / 200 | history length allowed for normal users |
| `--seed` | 42 | same seed gives the same sample |

Feature mapping: `failed_attempts` = failed logins by the user in the last 24 h; `unique_ips_24h` = distinct IPs in the
last 24 h; `new_device` = browser+OS+device type never seen for the user; `country_changed` = country differs from the
user's previous login; `login_hour` = hour of the timestamp. A user's first event has no history, so those two flags
are 0. Expect lower scores than on the synthetic data; that is the honest result. Because timestamps and IPs are
generated, `login_hour` and `unique_ips_24h` may carry less real signal than in production logs.

## Architecture

```
CSV -> React (Vite + TS + Recharts) --/api/*--> FastAPI
                                                 | validation.py    strict schema/range checks
                                                 | model.py         versioned Isolation Forest
                                                 | rules.py         transparent rule baseline
                                                 | uba.py           per-user baselines (past events only)
                                                 | investigation.py severity points, evidence, steps
                                                 | reports.py       offline Markdown/text reports (+ optional llm.py)
                                                 v
                                           store.py -> SQLite (scans, events, status, notes)
```
Scores are stored once. Changing the threshold re-derives flags, metrics and severities from the
stored scores, so no re-upload or re-scoring is needed.

| Layer | Tech |
|---|---|
| Frontend | React 18, TypeScript, Vite, Recharts |
| API | FastAPI, Pydantic |
| Data / ML | Pandas, NumPy, scikit-learn (IsolationForest), joblib |
| Storage | SQLite via Python's standard `sqlite3` (no new dependencies) |
| Tests | pytest + FastAPI TestClient (temporary SQLite DB per test), GitHub Actions CI |

## Quick start

Requires Python 3.10+ and Node 18+.

### Windows (PowerShell)

```powershell
# Terminal 1 - backend (from the repo root)
cd backend
py -m venv .venv
.venv\Scripts\Activate.ps1           # if blocked: Set-ExecutionPolicy -Scope Process Bypass
pip install -r requirements-dev.txt
python -m scripts.generate_data      # writes ..\data\*.csv
python -m pytest -q                  # run the tests
uvicorn app.main:app --reload --port 8001   # API docs: http://127.0.0.1:8001/docs

# Terminal 2 - frontend (from the repo root)
cd frontend
npm install
npm run dev                          # http://localhost:5173 (proxies /api to :8001)
```

### Optional LLM summary

To enable optional Gemini summaries, copy `backend/.env.example` to `backend/.env`, set `GEMINI_API_KEY`, and restart
the backend. The backend loads this file at startup; environment variables already set by the process take precedence.
Only aggregate statistics are sent to Gemini, with no raw rows, usernames or IPs. Without a key, the offline template
report is used. This project does not use RAG or fine-tuning.

Optional settings (PowerShell, current session only; these override values in `.env`):
```powershell
$env:SAD_DB_PATH = "C:\data\sad\scans.db"      # default: <repo>\var\scans.db
$env:SAD_LLM_ENABLED = "1"
$env:SAD_LLM_MODEL = "gemini-3.5-flash-lite"   # optional; override if needed for your account
$env:SAD_LLM_TIMEOUT = "60"                    # optional; clamped to 10-300 seconds
uvicorn app.main:app --reload
```

Run commands from the right folder (backend for uvicorn, frontend for npm). After restarting the backend,
reload the dashboard so it fetches `/api/config` again. The optional summary is enabled only when
`SAD_LLM_ENABLED=1` and `GEMINI_API_KEY` are both available to the backend process.

If the LLM falls back, read `X-LLM-Reason` and the backend log line; try `SAD_LLM_MODEL=gemini-3.5-flash-lite`.
The reason is a short code such as `http_401`, `http_404`, `timeout`, `network`, `bad_json`, `empty_response`,
or `max_tokens`. Logs never include the key or request/response body.

Troubleshooting:

- `ModuleNotFoundError numpy._core`: delete `backend\models\isolation_forest.joblib` or let the app retrain.
- Check `backend/.env` has `SAD_LLM_ENABLED=1` and a valid `GEMINI_API_KEY`; restart the backend after editing it.
- Never paste the key into a command or chat.

### macOS / Linux

```bash
cd backend && python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt && python -m scripts.generate_data && python -m pytest -q
uvicorn app.main:app --reload
# second terminal
cd frontend && npm install && npm run dev
```

The first request trains and saves the baseline model if `backend/models/isolation_forest.joblib` is
missing (or run `python -m scripts.train_model`). `python -m scripts.evaluate` prints the held-out
comparison of Isolation Forest vs rules.

> **Ports:** the frontend proxies `/api` to `http://127.0.0.1:8001`. If you run the backend on another port, set
> `$env:SAD_API_URL = "http://127.0.0.1:8000"` (PowerShell) or `export SAD_API_URL=http://127.0.0.1:8000` before
> `npm run dev`. Port 8000 is blocked on some Windows machines (`WinError 10013`); 8001 avoids that.

### Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Copilot / Feedback show **"does not have this feature"** or a bare *Not Found* | The frontend is talking to an **older backend** (often one still running on another port). Check `http://127.0.0.1:8001/docs` lists `/api/scans/{scan_id}/copilot`. Stop every backend (`netstat -ano \| findstr :8000`, `taskkill /PID <id> /F`), start this one, restart `npm run dev`, hard-refresh (Ctrl+Shift+R). |
| **Cannot reach the API** | Backend not running, or the proxy port differs from the backend port (see *Ports* above). |
| `WinError 10013` on start | Windows reserved or another program uses that port. Use `--port 8001`. |
| `numpy._core` / pickle error on start | Delete `backend/models/isolation_forest.joblib`; it retrains automatically. |

### Using the dashboard

1. **Try sample data** (or upload a CSV). Pick *baseline* or *batch* mode and a user-baseline minimum history.
2. **Overview**: KPIs, severity counts, hourly chart, metrics, filterable events table, CSV export.
3. **Alerts**: filter by detector/severity/status/user; click a row for evidence, severity points,
   user-baseline findings and suggested steps; change status and add notes.
4. **Model & threshold**: move the slider (live preview), use label-free presets, *Apply* to persist.
5. **Users**: per-user profile, hour histogram, deviations from the user's own earlier behaviour.
6. **AI Copilot**: search alerts in plain English and ask questions about the scan.
7. **Feedback**: after marking at least 8 false positives and 8 escalated alerts, preview training, check the
   cross-validated quality numbers and learned weights, then *Activate*. *Roll back* undoes it.
8. **Report**: preview or download an incident report (`.md` / `.txt`).
9. **History**: reopen or delete saved scans.

## API

Interactive docs at `/docs`. All v1 endpoints keep their paths and response shapes; v2 only adds fields and endpoints.

| Method & path | Purpose |
|---|---|
| `GET /api/health` | Liveness check |
| `GET /api/config` | Statuses, severity policy, limits, whether the optional LLM is configured |
| `GET /api/sample` | Download the bundled synthetic CSV |
| `POST /api/analyze?mode=&threshold=&uba_min_history=` | Upload CSV, score, persist, return the full scan (v1 shape plus `model_threshold`, `severity_counts`, ...) |
| `GET /api/scans?limit=&offset=` | Recent scans (plain list, as in v1) |
| `GET /api/scans/{id}` | Full saved scan |
| `GET /api/history?page=&page_size=&q=` | Paginated, searchable scan history |
| `DELETE /api/scans/{id}` | Delete a scan with its events and notes |
| `GET /api/scans/{id}/evaluate?threshold=` | Preview flags, IF-vs-rules metrics, agreement and threshold sweep (changes nothing) |
| `PUT /api/scans/{id}/threshold` | Persist a new active threshold (`0 < t < 1`) |
| `GET /api/scans/{id}/alerts` | Paginated alerts: `detector`, `severity`, `status`, `username`, `q`, `page`, `page_size` |
| `GET /api/scans/{id}/alerts/{row}` | Evidence, severity factors, steps, caveats, user-baseline result, notes |
| `PATCH /api/scans/{id}/alerts/{row}` | Set status: `new, in_review, escalated, false_positive, resolved` |
| `POST /api/scans/{id}/alerts/{row}/notes` | Add a note (1-2000 chars) |
| `GET /api/scans/{id}/users`, `GET .../user-profile?username=` | User list and per-user profile with deviations |
| `GET /api/scans/{id}/report?format=md/txt&top=&include_notes=&row=&use_llm=&download=` | Incident report |
| `POST /api/scans/{id}/nl-search` `{query}` | Plain-English search: returns the interpreted filters and matching flagged alerts |
| `POST /api/scans/{id}/copilot` `{question, use_llm}` | Grounded Q&A about one scan (`engine` is `offline` or `gemini`; `sources` lists cited rows) |
| `GET /api/feedback/summary` | Feedback counts, quality-gate settings, active triage model |
| `POST /api/feedback/train` `{activate}` | Preview (default) or activate a triage model learned from false-positive / escalated alerts |
| `POST /api/feedback/rollback` | Restore the previous triage model, or switch learned priority off |

**Required CSV columns:** `failed_attempts, login_hour, unique_ips_24h, new_device, country_changed`.
**Optional:** `label` (0/1, evaluation only, never a model input), `username` + `timestamp` (enable user
baselines), and any pass-through columns (`event_id, source_ip`, ...).

Errors: 400 bad/empty file · 404 unknown scan/alert/user · 413 too large (5 MB / 50k rows) · 422 invalid values.

## Severity policy (transparent, not a probability)

Severity is the sum of the points below, applied only to events flagged by a detector. Bands:
low 1-3, medium 4-6, high 7-9, critical 10+.

| Signal | Points |
|---|---|
| Isolation Forest score >= threshold / exceeds it by >= 0.05 | 2 / +1 |
| Rule baseline triggered | 1 |
| failed_attempts >= 8 / 5-7 | 2 / 1 |
| unique_ips_24h >= 4 | 1 |
| new device AND country changed / only one | 2 / 1 |
| login_hour <= 5 | 1 |
| >= 2 / 1 deviations from the user's own earlier history | 2 / 1 |

Overlapping signals deliberately reinforce each other. Severity is a triage priority for analysts.

## User behaviour analytics: how leakage is avoided

Each event is compared only with that user's events that sort *before* it (by timestamp, then file
position): expanding mean/std for failed attempts and IPs (z >= 3, std floored at 1), the share of prior
logins within +/-2 hours, and prior new-device/country-change rates. Users with fewer than `min_history`
earlier events get `insufficient_history` and **no** deviations. If timestamps are missing or
unparseable, file order is assumed chronological and the UI and report say so. Tests prove that
truncating or altering future rows never changes earlier results.

## Project layout

```
backend/app/        main + routes_v2 + routes_ai (API) · nlsearch · copilot · triage (AI layer) · service · store (SQLite) · validation · model · rules · uba ·
                    investigation · evaluation · reports · llm (optional) · synthetic · schemas · config
backend/scripts/    generate_data · train_model · evaluate
backend/tests/      API, model, history, threshold, investigation, UBA, report, plain-English search, copilot and feedback tests (temp DB per test)
frontend/src/       App (tabs) · api · csv · types · components/{UploadForm,SummaryCards,AnomalyChart,EvaluationPanel,
                    ResultsTable,AlertsPanel,CopilotPanel,FeedbackPanel,ThresholdPanel,UsersPanel,HistoryPanel,ReportPanel,Badges}
data/               synthetic sample CSVs (labeled + unlabeled)
docs/               interview-prep material (start with docs/00_START_HERE.md)
```

## Key design decisions

- **Versioned baseline model** instead of re-fitting per upload, so a score means the same thing
  between uploads. `batch` mode is kept to show the trade-off.
- **Labels never reach the model.** `FEATURES` is an explicit allow-list; a test asserts it.
- **Honest evaluation:** held-out test set with a different seed, precision/recall/F1/AUC and a
  confusion matrix for both the model and a rule baseline, plus recall per attack type.
- **Strict validation** with clear 4xx errors; bounded file reads; bounded in-memory store.
- **Security hygiene:** explicit CORS origins; parameterised SQL only (ORDER BY is fixed text); strict
  Pydantic validation (enums for status/severity/detector, bounded pages, note length); no secrets in
  source (the LLM key is read from the environment only); untrusted text (usernames, filenames, notes) is
  escaped in reports and rendered as plain text in the UI (no `innerHTML`, no Markdown renderer);
  CSV/formula-injection protection on export; `nosniff` on report responses; documentation-range IPs.
- **Human control:** no endpoint blocks, locks or changes anything. Steps and report actions are
  suggestions that explicitly require an authorised person.
- **Label-leakage guard:** labels never influence scores, flags, suggested thresholds or user
  baselines. Tests compare results with, without and with shuffled labels.
- **Optional LLM:** disabled unless `SAD_LLM_ENABLED=1` and `GEMINI_API_KEY` are both set.
  *Report summary:* only aggregate counts, the active threshold and severity totals are sent (no usernames, IPs,
  timestamps, filenames, event IDs or notes); output appears in a section labelled *unverified* and never replaces
  the evidence. *Copilot (Gemini mode):* sends aggregate counts plus the feature values, severity and a sanitised
  username for the top 15 alerts and top 5 users. Source IPs, event ids, timestamps, filenames and notes are never
  sent, and the model is told to treat the context as untrusted data. Tick "Use Gemini" off in the Copilot tab to
  stay fully offline. Any failure falls back to the offline template or offline assistant.
- **Feedback model is advisory:** logistic regression on the five features plus the Isolation Forest score. It
  only adds a learned priority; it never changes a status, hides an alert or blocks anything. Activation requires
  cross-validated AUC >= 0.75 and at most 5% of escalated alerts ranked "likely benign". Feedback is a biased
  sample (only alerts analysts chose to review) and `resolved` is ignored because it does not say which way the
  decision went.

## Results on the synthetic held-out set (10k rows, 4% simulated attacks)

| Detector | Precision | Recall | F1 |
|---|---|---|---|
| Isolation Forest | ~0.79 | ~0.97 | ~0.87 |
| Rule baseline | ~0.95 | ~0.76 | ~0.84 |

The forest catches more attacks (recall) but raises more false alarms; the rules are precise but
miss subtler patterns. This precision/recall trade-off is exactly what an analyst team tunes.
Numbers vary slightly by scikit-learn version. **Synthetic labels do not prove real-world effectiveness.**

## Limitations / next steps

- **Not production-ready:** no authentication or authorisation, no per-user separation of data, no rate
  limiting, no audit log, no malware scanning of uploads, and SQLite is single-node and unencrypted at
  rest. Put it behind an authenticating proxy before any shared use, and use synthetic data only.
- Anomaly scores are relative rankings from an unsupervised model, **not calibrated probabilities**;
  flags are **not proof of attack**. Severity is a heuristic triage priority, not a risk estimate.
- Evidence is limited to the CSV columns. The tool does no IP reputation, geolocation or threat intel.
- Metrics from synthetic labels demonstrate method, not real-world performance. Do not choose a
  threshold by maximising F1 on the same labels (the UI warns; presets are label-free).
- User baselines need history; sparse users get no deviation findings. Baselines are simple statistics
  (means, hour windows, rates), not a learned user model, and ignore seasonality or role changes.
- Alert listing computes severity in Python over matching events (fine at the 50k-row limit; use a real
  database or materialised columns beyond that). Review reasons are rules, not model explanations.
- The UI was type-checked and built, and the API was exercised end to end, but there are no automated
  browser (UI) tests yet.
- Next: SHAP/feature attributions, PostgreSQL, auth + roles, per-tenant baselines, an analyst feedback
  loop, drift monitoring, Playwright UI tests.
