import pytest

from app.nlsearch import parse_query


@pytest.mark.parametrize("text,expected", [
    ("critical alerts at night with a new device for user_044",
     {"severity": "critical", "hour_min": 0, "hour_max": 5, "new_device": 1, "username": "user_044"}),
    ("high severity logins from a different country", {"severity": "high", "country_changed": 1}),
    ("more than 8 failed attempts", {"failed_min": 9}),
    ("at least 5 failed logins and many ips", {"failed_min": 5, "ips_min": 4}),
    ("logins between 2 and 5 with new device and country changed",
     {"hour_min": 2, "hour_max": 5, "new_device": 1, "country_changed": 1}),
    ("escalated alerts top 5", {"status": "escalated", "limit": 5}),
    ("unreviewed high alerts at 3am", {"severity": "high", "hour_min": 3, "hour_max": 3, "status": "new"}),
    ("rule baseline flags only", {"detector": "rules"}),
    ("credential stuffing", {"ips_min": 4}),
])
def test_parser_extracts_filters(text, expected):
    assert parse_query(text)["filters"] == expected


def test_unrelated_text_yields_no_filters():
    r = parse_query("what is the weather like")
    assert r["filters"] == {} and r["interpreted"] == []


def test_new_device_is_not_mistaken_for_status_new():
    assert "status" not in parse_query("new device logins")["filters"]


def test_limit_is_capped():
    assert parse_query("top 5000 alerts")["filters"]["limit"] == 100


def test_search_applies_filters_and_explains_them(client, scan_id):
    r = client.post(f"/api/scans/{scan_id}/nl-search", json={"query": "new device and country changed at night"})
    assert r.status_code == 200
    body = r.json()
    assert body["understood"] and "new_device = 1" in body["interpreted"]
    for it in body["items"]:
        d = it["data"]
        assert d["new_device"] == 1 and d["country_changed"] == 1 and 0 <= d["login_hour"] <= 5


def test_search_severity_filter(client, scan_id):
    body = client.post(f"/api/scans/{scan_id}/nl-search", json={"query": "high alerts"}).json()
    assert body["total"] > 0 and all(i["severity"] == "high" for i in body["items"])


def test_search_limit_and_total(client, scan_id):
    body = client.post(f"/api/scans/{scan_id}/nl-search", json={"query": "top 3 alerts"}).json()
    assert body["shown"] == len(body["items"]) == 3 and body["total"] >= 3


def test_not_understood_is_reported_not_guessed(client, scan_id):
    body = client.post(f"/api/scans/{scan_id}/nl-search", json={"query": "banana smoothie"}).json()
    assert body["understood"] is False and body["interpreted"] == []


def test_search_validation_and_404(client, scan_id):
    assert client.post(f"/api/scans/{scan_id}/nl-search", json={"query": ""}).status_code == 422
    assert client.post("/api/scans/nope/nl-search", json={"query": "high"}).status_code == 404
