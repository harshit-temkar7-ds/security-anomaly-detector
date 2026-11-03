"""Offline, template-based incident reports (Markdown or plain text).

Every statement is generated from stored scan data. Free text from the data or from analysts
(usernames, filenames, notes) is escaped so it cannot inject Markdown/HTML structure.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Optional

from .investigation import BANDS_TEXT, SEVERITY_ORDER, SEVERITY_POLICY
from .llm import model_name

_ESC = re.compile(r"([\\`*_\[\]<>|#~!])")


def esc(value: Any) -> str:
    """Escape Markdown specials and flatten newlines in untrusted text."""
    return _ESC.sub(r"\\\1", re.sub(r"\s+", " ", str(value))).strip()


def _table(header: list[str], rows: list[list[Any]]) -> list[str]:
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return out + [""]


def facts_for_llm(ctx: dict) -> str:
    """Aggregate-only facts (no identifiers) for the optional LLM summary."""
    s = ctx["scan"]
    sev = ", ".join(f"{k}: {v}" for k, v in ctx["severity_counts"].items() if v) or "none flagged"
    return (f"Aggregate counts: {s['rows_analyzed']} login events, {s['anomalies_flagged']} flagged by the "
            f"model, {s['rule_flags']} flagged by the rule baseline. Active threshold: {s['threshold']:.4f}. "
            f"Severity totals: {sev}.")


def build_report(ctx: dict[str, Any], fmt: str = "md", narrative: Optional[str] = None) -> str:
    s, ev = ctx["scan"], ctx["evaluation"]
    flagged, rows = s["anomalies_flagged"], s["rows_analyzed"]
    L: list[str] = [f"# Incident Report: scan {esc(s['scan_id'])}", "",
                    "> Triage report generated offline from stored scan data. Anomaly flags are leads for a "
                    "human analyst, not proof of an attack. Scores are not calibrated probabilities. "
                    "No remediation has been performed by this tool.", ""]

    L += ["## 1. Scan overview", ""] + _table(["Item", "Value"], [
        ["File", esc(s["filename"])], ["Scan time (UTC)", esc(s["created_at"])],
        ["Report generated (UTC)", datetime.now(timezone.utc).isoformat(timespec="seconds")],
        ["Model", f"Isolation Forest ({esc(s['mode'])} mode, version {esc(s['model_version'])})"],
        ["Active threshold", f"{s['threshold']:.4f} (model default {s['model_threshold']:.4f})"],
        ["Events analysed", rows], ["Flagged by model", f"{flagged} ({flagged / rows:.1%})"],
        ["Flagged by rule baseline", s["rule_flags"]], ["Labels present", "yes" if s["has_labels"] else "no"],
        ["User-baseline ordering", esc(s["uba_basis"])],
    ])

    sev = ctx["severity_counts"]
    sev_text = ", ".join(f"{sev.get(k, 0)} {k}" for k in reversed(SEVERITY_ORDER[1:]))
    st = ctx["status_counts"]
    open_n = sum(v for k, v in st.items() if k in ("new", "in_review", "escalated"))
    L += ["## 2. Executive summary", "",
          f"{flagged} of {rows} events ({flagged / rows:.1%}) were flagged by the Isolation Forest at the "
          f"active threshold. Severity (a transparent points-based triage priority): {sev_text}. "
          f"{open_n} flagged alerts are still open (new, in review or escalated).", ""]
    if narrative:
        safe_narrative = "\n".join(esc(line) for line in narrative.splitlines())
        L += [f"### Optional LLM-written summary (unverified, model: {esc(model_name())})", "",
              "_Generated from aggregate counts only. Verify against the evidence below._", "",
              safe_narrative, ""]

    L += ["## 3. Detector comparison", ""]
    ag = ctx["agreement"]
    L += _table(["Both flagged", "Model only", "Rules only", "Neither"],
                [[ag["both"], ag["model_only"], ag["rules_only"], ag["neither"]]])
    if ev:
        def r(name, m):
            c = m["confusion_matrix"]
            return [name, m["precision"], m["recall"], m["f1"], m["roc_auc"] if m["roc_auc"] is not None else "n/a",
                    f"TP {c['tp']} / FP {c['fp']} / FN {c['fn']} / TN {c['tn']}"]
        L += _table(["Detector", "Precision", "Recall", "F1", "ROC AUC", "Confusion"],
                    [r("Isolation Forest", ev["model"]), r("Rule baseline", ev["rules"])])
        L += [f"Metrics use the file's own label column ({ev['positives']} positives). {esc(ev['note'])}", ""]
    else:
        L += ["No label column was provided, so precision and recall cannot be computed.", ""]

    L += ["## 4. Key findings", ""]
    if not ctx["alerts"]:
        L += ["No alerts were selected for this report.", ""]
    for a in ctx["alerts"]:
        L += [f"### Alert row {a['row']}: {a['severity'].upper()} ({a['points']} points)", ""]
        if a["context"]:
            L.append("**Context:** " + "; ".join(f"{esc(k)} = {esc(v)}" for k, v in a["context"].items()))
        L.append(f"**Anomaly score:** {a['score']:.3f} (threshold {s['threshold']:.3f}). "
                 f"**Analyst status:** {esc(a['status'])}.")
        L += ["", "**Evidence:**"] + [f"- {esc(f['evidence'])} (+{f['points']})" for f in a["factors"]] + [""]
        if a["limitations_event"]:
            L += ["**Caveats for this alert:**"] + [f"- {esc(x)}" for x in a["limitations_event"]] + [""]
        L += ["**Suggested investigation steps (for an analyst to decide):**"]
        L += [f"{i}. {esc(x)}" for i, x in enumerate(a["steps"], 1)] + [""]
        if a.get("notes"):
            L += ["**Analyst notes:**"] + [f"- {esc(n['created_at'])} {esc(n['author'])}: {esc(n['note'])}"
                                         for n in a["notes"][-5:]] + [""]

    L += ["## 5. Uncertainty and limitations", ""]
    L += [f"- {esc(x)}" for x in ctx["uncertainty"]] + [""]

    L += ["## 6. Recommended actions (require human approval)", ""]
    L += [f"{i}. {esc(x)}" for i, x in enumerate(ctx["actions"], 1)] + [""]

    L += ["## Appendix: severity policy", "", "Severity is the sum of the points below, applied only to "
          "events flagged by a detector. Bands: " + ", ".join(f"{k} = {v}" for k, v in BANDS_TEXT.items()) + ".", ""]
    L += _table(["Signal", "Points", "Rule"], [[p["factor"], p["points"], esc(p["rule"])] for p in SEVERITY_POLICY])

    md = "\n".join(L).rstrip() + "\n"
    return md if fmt == "md" else to_text(md)


def to_text(md: str) -> str:
    out = []
    for line in md.splitlines():
        if re.fullmatch(r"\|[-| :]+\|", line):
            continue
        if line.startswith("|"):
            line = line.strip("|").strip().replace(" | ", "  |  ")
        line = re.sub(r"^#{1,6}\s*", "", line)
        line = re.sub(r"^>\s?", "", line)
        line = line.replace("**", "")
        line = re.sub(r"\\([\\`*_\[\]<>|#~!])", r"\1", line)
        out.append(line.strip("_") if line.startswith("_") and line.endswith("_") else line)
    return "\n".join(out)
