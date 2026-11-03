from app import llm


NOTICE = "LLM summary could not be generated; showing the offline template report."


def test_unavailable_llm_returns_template_and_fallback_notice(client, scan_id, monkeypatch):
    monkeypatch.delenv("SAD_LLM_ENABLED", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    response = client.get(f"/api/scans/{scan_id}/report", params={"use_llm": "true"})

    assert response.status_code == 200
    assert response.headers["x-llm-used"] == "false"
    assert response.headers["x-llm-reason"] == "disabled"
    assert "## 4. Key findings" in response.text
    assert "not proof of an attack" in response.text
    assert NOTICE in response.text


def test_llm_exception_returns_template_and_fallback_notice(client, scan_id, monkeypatch):
    monkeypatch.setattr(llm, "available", lambda: True)

    def fail(_facts):
        raise RuntimeError("private provider detail")

    monkeypatch.setattr("app.routes_v2.llm.complete_with_reason", fail)
    response = client.get(f"/api/scans/{scan_id}/report", params={"use_llm": "true", "download": "true"})

    assert response.status_code == 200
    assert response.headers["x-llm-used"] == "false"
    assert response.headers["x-llm-reason"] == "network"
    assert "## 4. Key findings" in response.text
    assert "not proof of an attack" in response.text
    assert NOTICE in response.text
    assert "private provider detail" not in response.text
