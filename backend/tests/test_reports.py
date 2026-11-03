import re
import io
import json
import urllib.error
import urllib.parse

import pytest

from app import llm
from app.reports import esc, facts_for_llm, to_text

from .conftest import make_user_csv, post_csv


def get(client, sid, **params):
    return client.get(f"/api/scans/{sid}/report", params=params)


def test_markdown_report_has_all_sections(client, scan_id):
    r = get(client, scan_id)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/markdown")
    for h in ("## 1. Scan overview", "## 2. Executive summary", "## 3. Detector comparison", "## 4. Key findings",
              "## 5. Uncertainty and limitations", "## 6. Recommended actions", "## Appendix: severity policy"):
        assert h in r.text
    assert "not proof of an attack" in r.text and "Evidence:" in r.text
    assert "Suggested investigation steps (for an analyst to decide)" in r.text
    assert r.headers["x-content-type-options"] == "nosniff"


def test_report_states_uncertainty_and_requires_human_approval(client, scan_id):
    t = get(client, scan_id).text
    assert "not calibrated probabilities" in t and "require human approval" in t.lower()
    assert "recommends no automatic remediation" in t


def test_report_without_labels_says_metrics_unknown(client):
    sid = post_csv(client, make_user_csv()).json()["scan_id"]
    t = get(client, sid).text
    assert "No label column was provided" in t and "detection quality" in t


def test_report_with_labels_has_metrics_table(client, scan_id):
    t = get(client, scan_id).text
    assert "Isolation Forest" in t and "Rule baseline" in t and "Precision" in t and "TP " in t


def test_report_mentions_insufficient_baselines(client):
    sid = post_csv(client, make_user_csv(n_stable=4)).json()["scan_id"]
    assert "no usable user baseline" in get(client, sid).text


def test_report_reflects_threshold_status_and_notes(client, scan_id):
    row = client.get(f"/api/scans/{scan_id}/alerts").json()["items"][0]["row"]
    client.patch(f"/api/scans/{scan_id}/alerts/{row}", json={"status": "escalated"})
    client.post(f"/api/scans/{scan_id}/alerts/{row}/notes", json={"note": "called the owner", "author": "kim"})
    client.put(f"/api/scans/{scan_id}/threshold", json={"threshold": 0.7})
    t = get(client, scan_id, top=100).text
    assert "0.7000" in t and "called the owner" in t and "escalated" in t
    assert "called the owner" not in get(client, scan_id, include_notes="false").text


def test_single_alert_report(client, scan_id):
    row = client.get(f"/api/scans/{scan_id}/alerts").json()["items"][0]["row"]
    t = get(client, scan_id, row=row).text
    assert t.count("### Alert row") == 1 and f"Alert row {row}:" in t
    assert get(client, scan_id, row=999999).status_code == 404


def test_top_parameter_limits_detail(client, scan_id):
    assert get(client, scan_id, top=3).text.count("### Alert row") == 3
    assert "Only the top 3" in get(client, scan_id, top=3).text
    assert get(client, scan_id, top=0).status_code == 422 and get(client, scan_id, top=101).status_code == 422


def test_text_format_has_no_markdown_markup(client, scan_id):
    r = get(client, scan_id, format="txt")
    assert r.headers["content-type"].startswith("text/plain")
    assert not re.search(r"^#{1,6} ", r.text, re.M) and "**" not in r.text and "|---" not in r.text
    assert "Incident Report" in r.text and "Uncertainty and limitations" in r.text
    assert get(client, scan_id, format="html").status_code == 422


def test_download_header_uses_safe_filename(client, scan_id):
    r = get(client, scan_id, download="true", format="txt")
    assert r.headers["content-disposition"] == f'attachment; filename="incident_report_{scan_id}.txt"'


def test_untrusted_text_is_escaped_in_reports(client):
    csv = make_user_csv(user="<img src=x onerror=alert(1)>").replace("alice", "x")
    sid = post_csv(client, csv, name="<b>evil</b>[link](javascript:alert(1)).csv").json()["scan_id"]
    row = client.get(f"/api/scans/{sid}/alerts", params={"detector": "either"}).json()["items"][0]["row"]
    client.post(f"/api/scans/{sid}/alerts/{row}/notes", json={"note": "[click](http://evil) <script>x</script>", "author": "<i>a</i>"})
    t = get(client, sid).text
    assert not re.search(r"(?<!\\)<", t), "unescaped < found"        # every '<' must be backslash-escaped
    assert not re.search(r"(?<!\\)\]\(", t), "unescaped markdown link found"
    assert "\\<script\\>" in t and "\\[click\\]" in t


def test_esc_helper_flattens_and_escapes():
    assert esc("a\nb *c* `d` <e> [f](g) | h") == r"a b \*c\* \`d\` \<e\> \[f\](g) \| h"
    assert to_text("## Title\n| a | b |\n|---|---|\n| 1 | 2 |\n**x**").splitlines() == ["Title", "a  |  b", "1  |  2", "x"]


def test_llm_is_optional_and_off_by_default(client, scan_id, monkeypatch):
    monkeypatch.delenv("SAD_LLM_ENABLED", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    assert llm.available() is False and llm.complete("x") is None
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("SAD_LLM_ENABLED", "1")
    assert llm.available() is False
    cfg = client.get("/api/config").json()
    assert cfg["llm_available"] is False
    r = get(client, scan_id, use_llm="true")
    assert r.status_code == 200 and r.headers["x-llm-used"] == "false" and "LLM-written" not in r.text


def test_llm_needs_both_flag_and_key(monkeypatch):
    monkeypatch.setenv("SAD_LLM_ENABLED", "1")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    assert llm.available() is False
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    assert llm.available() is True


def test_gemini_request_uses_environment_key_and_response_text(monkeypatch):
    monkeypatch.setenv("SAD_LLM_ENABLED", "1")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    monkeypatch.delenv("SAD_LLM_MODEL", raising=False)
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def read(self):
            return json.dumps({"candidates": [{"content": {"parts": [{"text": "Summary."}]}}]}).encode()

    def fake_urlopen(req, timeout):
        captured.update(url=req.full_url, body=json.loads(req.data), key=req.get_header("X-goog-api-key"), timeout=timeout)
        return Response()

    monkeypatch.setattr(llm.urllib.request, "urlopen", fake_urlopen)
    assert llm.complete("Only aggregate facts") == "Summary."
    assert captured["url"].endswith("/models/gemini-3.5-flash-lite:generateContent")
    assert captured["body"]["contents"] == [{"role": "user", "parts": [{"text": "Only aggregate facts"}]}]
    assert captured["key"] == "test-key-not-real" and captured["timeout"] == 60
    assert captured["body"]["generationConfig"]["maxOutputTokens"] >= 2048
    assert urllib.parse.urlsplit(captured["url"]).scheme == "https"
    assert urllib.parse.urlsplit(captured["url"]).query == ""
    assert "test-key-not-real" not in captured["url"]
    monkeypatch.setenv("SAD_LLM_MODEL", "account-selected-model")
    assert llm.complete("Only aggregate facts") == "Summary."
    assert captured["url"].endswith("/models/account-selected-model:generateContent")


def test_gemini_key_whitespace_and_timeout_settings(monkeypatch):
    monkeypatch.setenv("SAD_LLM_ENABLED", "1")
    monkeypatch.setenv("GEMINI_API_KEY", "  safe-key\r\n")
    assert llm.available()
    monkeypatch.setenv("GEMINI_API_KEY", "bad key")
    assert not llm.available()
    monkeypatch.setenv("GEMINI_API_KEY", "safe-key")
    monkeypatch.setenv("SAD_LLM_TIMEOUT", "1")
    assert llm.timeout_seconds() == 10
    monkeypatch.setenv("SAD_LLM_TIMEOUT", "999")
    assert llm.timeout_seconds() == 300
    monkeypatch.setenv("SAD_LLM_TIMEOUT", "not-a-number")
    assert llm.timeout_seconds() == 60


def test_gemini_joins_all_text_parts_and_reports_max_tokens(monkeypatch):
    monkeypatch.setenv("SAD_LLM_ENABLED", "1")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")

    class Response:
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def read(self):
            return b'{"candidates":[{"content":{"parts":[{"text":"one"},{"text":" two"}]}}]}'

    monkeypatch.setattr(llm.urllib.request, "urlopen", lambda *args, **kwargs: Response())
    assert llm.complete_with_reason("aggregate facts") == ("one two", "")

    class MaxTokensResponse(Response):
        def read(self): return b'{"candidates":[{"finishReason":"MAX_TOKENS","content":{"parts":[]}}]}'

    monkeypatch.setattr(llm.urllib.request, "urlopen", lambda *args, **kwargs: MaxTokensResponse())
    assert llm.complete_with_reason("aggregate facts") == (None, "max_tokens")


def test_gemini_outgoing_body_contains_only_aggregate_report_facts(monkeypatch):
    monkeypatch.setenv("SAD_LLM_ENABLED", "1")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    private = ["sentinel-user", "203.0.113.77", "2026-11-02T10:20:30Z",
               "sentinel-file.csv", "sentinel-event-id", "sentinel-analyst-note"]
    ctx = {
        "scan": {"rows_analyzed": 10, "anomalies_flagged": 2, "rule_flags": 1,
                 "threshold": 0.625, "username": private[0], "source_ip": private[1],
                 "created_at": private[2], "filename": private[3], "event_id": private[4],
                 "notes": private[5]},
        "severity_counts": {"high": 1, "low": 1},
        "alerts": [{"context": {"username": private[0], "source_ip": private[1],
                                 "timestamp": private[2], "event_id": private[4]},
                    "notes": [{"note": private[5]}]}],
    }
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def read(self):
            return b'{"candidates":[{"content":{"parts":[{"text":"ok"}]}}]}'

    def fake_urlopen(req, timeout):
        captured["body"] = req.data.decode()
        captured["key"] = req.get_header("X-goog-api-key")
        return Response()

    monkeypatch.setattr(llm.urllib.request, "urlopen", fake_urlopen)
    facts = facts_for_llm(ctx)
    assert llm.complete(facts) == "ok"
    assert all(item not in captured["body"] for item in private)
    assert "10 login events" in captured["body"] and "0.6250" in captured["body"]
    assert "high: 1" in captured["body"] and captured["key"] == "test-key-not-real"


def test_gemini_http_error_logs_status_without_secret_or_request(monkeypatch, caplog):
    monkeypatch.setenv("SAD_LLM_ENABLED", "1")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")

    def fail(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 401, "unauthorized", {}, io.BytesIO(b"sensitive provider body"))

    monkeypatch.setattr(llm.urllib.request, "urlopen", fail)
    assert llm.complete("sensitive aggregate payload") is None
    assert "http_401" in caplog.text
    assert "test-key-not-real" not in caplog.text
    assert "sensitive aggregate payload" not in caplog.text
    assert "sensitive provider body" not in caplog.text


@pytest.mark.parametrize("failure", ["http", "timeout", "malformed_json", "empty_text", "blocked", "exception"])
def test_gemini_failures_fall_back_to_template(client, scan_id, monkeypatch, caplog, failure):
    monkeypatch.setenv("SAD_LLM_ENABLED", "1")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")

    class Response:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def read(self):
            return self.body

    def fail(req, timeout):
        if failure == "http":
            raise urllib.error.HTTPError(req.full_url, 404, "private response text", {}, io.BytesIO(b"private response text"))
        if failure == "timeout":
            raise TimeoutError("private timeout detail")
        if failure == "exception":
            raise RuntimeError("private exception detail")
        if failure == "malformed_json":
            body = b"not-json"
        elif failure == "empty_text":
            body = b'{"candidates":[{"content":{"parts":[{"text":"   "}]}}]}'
        else:
            body = b'{"candidates":[{"finishReason":"SAFETY"}]}'
        return Response(body)

    monkeypatch.setattr(llm.urllib.request, "urlopen", fail)
    response = get(client, scan_id, use_llm="true")
    assert response.status_code == 200
    assert response.headers["x-llm-used"] == "false"
    expected_reason = {"http": "http_404", "timeout": "timeout", "malformed_json": "bad_json",
                       "empty_text": "empty_response", "blocked": "empty_response",
                       "exception": "network"}[failure]
    assert response.headers["x-llm-reason"] == expected_reason
    assert "LLM-written" not in response.text and "## 4. Key findings" in response.text
    assert "test-key-not-real" not in caplog.text
    assert "private response text" not in caplog.text
    assert "private timeout detail" not in caplog.text
    assert "private exception detail" not in caplog.text


def test_llm_narrative_is_labelled_unverified_and_never_replaces_evidence(client, scan_id, monkeypatch):
    seen = {}
    monkeypatch.setenv("SAD_LLM_MODEL", "configured-model")
    narrative = "## forged\n[link](javascript:alert(1))\n- *first item*\n- second item"
    monkeypatch.setattr("app.routes_v2.llm.complete_with_reason",
                        lambda facts: (seen.setdefault("f", facts) and narrative, ""))
    r = get(client, scan_id, use_llm="true")
    assert r.headers["x-llm-used"] == "true"
    assert r.headers["x-llm-reason"] == ""
    assert "Optional LLM-written summary (unverified, model: configured-model)" in r.text
    assert "Evidence:" in r.text and "## 4. Key findings" in r.text      # template content still present
    assert r"\#\# forged" + "\n" + r"\[link\](javascript:alert(1))" + "\n" + r"- \*first item\*" + "\n- second item" in r.text
    assert "synthetic" in seen["f"].lower() or "events" in seen["f"]
    assert not re.search(r"user_\d+|203\.0\.113|192\.0\.2|198\.51\.100", seen["f"])   # no identifiers sent


def test_llm_failure_falls_back_to_template(client, scan_id, monkeypatch):
    monkeypatch.setattr("app.routes_v2.llm.complete_with_reason", lambda facts: (None, "timeout"))
    r = get(client, scan_id, use_llm="true")
    assert r.status_code == 200 and r.headers["x-llm-used"] == "false" and "LLM-written" not in r.text
    assert r.headers["x-llm-reason"] == "timeout"


def test_facts_for_llm_contain_only_aggregates():
    ctx = {"scan": {"rows_analyzed": 10, "anomalies_flagged": 2, "threshold": 0.6, "rule_flags": 1,
                    "has_labels": False}, "severity_counts": {"low": 1, "high": 1}}
    f = facts_for_llm(ctx)
    assert "10 login events" in f and "threshold: 0.6000" in f and "high: 1" in f


def test_no_secrets_in_source():
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    allowed = {".py", ".ts", ".tsx", ".js", ".mjs", ".md"}
    patterns = (r"AIza[0-9A-Za-z_-]{20,}", r"AQ\.[0-9A-Za-z_-]{20,}", r"sk-[A-Za-z0-9_-]{20,}")
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in allowed and path.name not in {".env.example"}:
            continue
        if {".venv", "node_modules", "dist", ".git"}.intersection(path.parts):
            continue
        content = path.read_text(encoding="utf-8", errors="ignore")
        assert not any(re.search(pattern, content) for pattern in patterns), path.relative_to(root)
    env_example = (root / "backend" / ".env.example").read_text(encoding="utf-8-sig")
    assert re.search(r"(?m)^# GEMINI_API_KEY=\s*$", env_example)
    app_source = (root / "backend" / "app" / "llm.py").read_text(encoding="utf-8")
    assert "GEMINI_API_KEY" in app_source and 'os.getenv("GEMINI_API_KEY"' in app_source


def test_config_endpoint(client):
    c = client.get("/api/config").json()
    assert c["statuses"] == ["new", "in_review", "escalated", "false_positive", "resolved"]
    assert c["severity_policy"] and "critical" in c["severity_bands"]
