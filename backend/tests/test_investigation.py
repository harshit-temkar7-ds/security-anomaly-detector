import re

import pytest

from app.investigation import assess, band

from .conftest import post_csv

BASE = {"failed_attempts": 0, "login_hour": 13, "unique_ips_24h": 1, "new_device": 0, "country_changed": 0}


def ev(**kw):
    return {**BASE, **kw}


def test_band_boundaries():
    assert [band(p) for p in (0, 1, 3, 4, 6, 7, 9, 10, 20)] == \
        ["none", "low", "low", "medium", "medium", "high", "high", "critical", "critical"]


def test_unflagged_event_is_none_and_has_no_claims():
    a = assess(ev(), score=0.40, threshold=0.65, rule_flag=False)
    assert a["severity"] == "none" and a["points"] == 0 and a["factors"] == []
    assert "Not flagged" in a["summary"]


def test_severity_points_are_transparent_sums():
    data = ev(failed_attempts=12, unique_ips_24h=6, new_device=1, country_changed=1, login_hour=2)
    a = assess(data, score=0.80, threshold=0.65, rule_flag=True)
    assert a["points"] == sum(f["points"] for f in a["factors"])
    assert {f["factor"] for f in a["factors"]} >= {"model_score", "score_margin", "rule_baseline",
                                                    "failed_attempts", "unique_ips_24h",
                                                    "device_location", "early_hours"}
    assert a["severity"] == "critical"


def test_single_weak_signal_is_low():
    a = assess(ev(login_hour=3), score=0.66, threshold=0.65, rule_flag=False)
    assert a["severity"] == "low" and a["points"] == 3


def test_never_invents_evidence_missing_fields():
    a = assess(ev(failed_attempts=9), 0.7, 0.65, True)          # no username/timestamp/ip in the event
    text = " ".join([a["summary"], *a["steps"], *(f["evidence"] for f in a["factors"])]).lower()
    for word in ("username", "user ", "ip address", "geolocation", "malware", "attacker", "botnet", "vpn "):
        assert word not in text or word == "user "
    assert a["context"] == {}
    assert "this account" in " ".join(a["steps"])


def test_context_only_contains_present_fields():
    a = assess({**ev(failed_attempts=9), "username": "u1", "source_ip": "203.0.113.5", "timestamp": "t"},
               0.7, 0.65, True)
    assert a["context"] == {"timestamp": "t", "username": "u1", "source_ip": "203.0.113.5"}


@pytest.mark.parametrize("kw", [dict(failed_attempts=7), dict(unique_ips_24h=5, new_device=1),
                                dict(country_changed=1, login_hour=1)])
def test_every_number_in_evidence_comes_from_the_event(kw):
    data = ev(**kw)
    a = assess(data, 0.80, 0.65, False)
    allowed = {str(v) for v in data.values()} | {"0.800", "0.650", "0.150", "0", "5", "8", "4", "6", "1", "7", "24", "00", "05", "59"}  # + fixed rule limits / field-name digits
    for f in a["factors"]:
        for num in re.findall(r"\d+(?:\.\d+)?", f["evidence"]):
            assert num in allowed, (f["factor"], num)


def test_no_automatic_remediation_language():
    a = assess(ev(failed_attempts=15, unique_ips_24h=7), 0.9, 0.65, True)
    steps = " ".join(a["steps"]).lower()
    assert "authorised" in steps or "authorized" in steps or "analyst" in steps
    assert not re.search(r"\b(automatically (block|lock|disable)|will block|has been blocked)\b", steps)
    assert "no automatic remediation" in steps


def test_detector_disagreement_is_called_out():
    a = assess(ev(failed_attempts=9), 0.40, 0.65, True)       # rules only
    assert any("disagree" in x for x in a["limitations"])


def test_limitations_always_state_scores_are_not_probabilities():
    assert any("not calibrated probabilities" in x for x in assess(ev(), 0.9, 0.65, False)["limitations"])


# ------------------------------------------------------------------ API
def test_alert_list_filters_sorting_and_pagination(client, scan_id):
    body = client.get(f"/api/scans/{scan_id}/alerts", params={"page_size": 10}).json()
    assert body["total"] > 10 and len(body["items"]) == 10
    order = ["none", "low", "medium", "high", "critical"]
    keys = [(order.index(i["severity"]), i["points"]) for i in body["items"]]
    assert keys == sorted(keys, reverse=True)
    crit = client.get(f"/api/scans/{scan_id}/alerts", params={"severity": "critical"}).json()
    assert all(i["severity"] == "critical" for i in crit["items"]) and crit["total"] == body["severity_counts"]["critical"]
    page2 = client.get(f"/api/scans/{scan_id}/alerts", params={"page_size": 10, "page": 2}).json()
    assert {i["row"] for i in page2["items"]}.isdisjoint({i["row"] for i in body["items"]})
    u = body["items"][0]["username"]
    by_user = client.get(f"/api/scans/{scan_id}/alerts", params={"username": u}).json()
    assert by_user["total"] >= 1 and all(i["username"] == u for i in by_user["items"])


def test_alert_detail_has_evidence_steps_and_caveats(client, scan_id):
    row = client.get(f"/api/scans/{scan_id}/alerts").json()["items"][0]["row"]
    d = client.get(f"/api/scans/{scan_id}/alerts/{row}").json()
    assert d["factors"] and d["steps"] and d["limitations"] and d["benign_possibilities"]
    assert d["points"] == sum(f["points"] for f in d["factors"])
    assert "not proof of an attack" in d["summary"]
    for f in d["factors"]:
        assert f["evidence"]


def test_status_workflow_and_validation(client, scan_id):
    row = client.get(f"/api/scans/{scan_id}/alerts").json()["items"][0]["row"]
    url = f"/api/scans/{scan_id}/alerts/{row}"
    assert client.get(url).json()["status"] == "new"
    for s in ("in_review", "escalated", "false_positive", "resolved"):
        assert client.patch(url, json={"status": s}).json()["status"] == s
    assert client.patch(url, json={"status": "deleted"}).status_code == 422
    assert client.patch(url, json={}).status_code == 422
    fp = client.get(f"/api/scans/{scan_id}/alerts", params={"status": "resolved"}).json()
    assert fp["total"] == 1 and fp["items"][0]["row"] == row


def test_notes_validation_and_storage_as_plain_text(client, scan_id):
    row = client.get(f"/api/scans/{scan_id}/alerts").json()["items"][0]["row"]
    url = f"/api/scans/{scan_id}/alerts/{row}/notes"
    payload = "<script>alert(1)</script> ok"
    r = client.post(url, json={"note": payload, "author": "sam"})
    assert r.status_code == 201 and r.json()["note"] == payload      # stored verbatim; UI renders as text
    assert client.post(url, json={"note": ""}).status_code == 422
    assert client.post(url, json={"note": "x" * 2001}).status_code == 422
    assert client.post(url, json={"note": "ok", "author": "a" * 65}).status_code == 422
    assert client.get(f"/api/scans/{scan_id}/alerts/{row}").json()["notes"][0]["author"] == "sam"


def test_not_found_cases(client, scan_id):
    assert client.get("/api/scans/nope/alerts").status_code == 404
    assert client.get(f"/api/scans/{scan_id}/alerts/999999").status_code == 404
    assert client.patch(f"/api/scans/{scan_id}/alerts/999999", json={"status": "new"}).status_code == 404
    assert client.post(f"/api/scans/{scan_id}/alerts/999999/notes", json={"note": "x"}).status_code == 404


def test_alert_filter_values_are_validated(client, scan_id):
    assert client.get(f"/api/scans/{scan_id}/alerts", params={"severity": "urgent"}).status_code == 422
    assert client.get(f"/api/scans/{scan_id}/alerts", params={"detector": "x"}).status_code == 422
    assert client.get(f"/api/scans/{scan_id}/alerts", params={"page_size": 500}).status_code == 422


def test_sql_injection_attempt_in_username_filter_is_inert(client, scan_id):
    r = client.get(f"/api/scans/{scan_id}/alerts", params={"username": "x' OR '1'='1"})
    assert r.status_code == 200 and r.json()["total"] == 0


def test_works_on_files_without_username_or_timestamp(client):
    csv = ("failed_attempts,login_hour,unique_ips_24h,new_device,country_changed\n"
           + "0,10,1,0,0\n" * 40 + "30,3,9,1,1\n")
    sid = post_csv(client, csv).json()["scan_id"]
    items = client.get(f"/api/scans/{sid}/alerts").json()["items"]
    assert items and items[0]["username"] is None
    d = client.get(f"/api/scans/{sid}/alerts/{items[0]['row']}").json()
    assert d["context"] == {} and d["uba"]["status"] == "unavailable"
    assert not any("username" in f["evidence"] for f in d["factors"])
