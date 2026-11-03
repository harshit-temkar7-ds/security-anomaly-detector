import pandas as pd

from app.config import FEATURES
from app.uba import compute_uba, user_profile
from app.validation import validate_features

from .conftest import make_user_csv, post_csv


def frame(csv_text: str) -> pd.DataFrame:
    from io import StringIO
    df = pd.read_csv(StringIO(csv_text))
    out = validate_features(df)
    for c in ("username", "timestamp"):
        if c in df:
            out[c] = df[c]
    return out


def test_detects_deviation_from_own_baseline_with_explanations():
    res, basis = compute_uba(frame(make_user_csv()), min_history=10)
    last = res[-1]
    assert basis == "timestamp" and last["status"] == "ok" and last["n_prior"] == 30
    feats = {d["feature"] for d in last["deviations"]}
    assert {"failed_attempts", "unique_ips_24h", "login_hour", "new_device", "country_changed"} <= feats
    assert all(d["detail"] and "prior" in d["detail"] for d in last["deviations"])
    assert "failed_attempts=20" in next(d["detail"] for d in last["deviations"] if d["feature"] == "failed_attempts")


def test_stable_history_has_no_deviations():
    res, _ = compute_uba(frame(make_user_csv(spike=False)), min_history=10)
    assert all(r["count"] == 0 for r in res)


def test_insufficient_history_makes_no_claims():
    res, _ = compute_uba(frame(make_user_csv(n_stable=5)), min_history=10)
    assert [r["status"] for r in res] == ["insufficient_history"] * 6
    assert all(r["deviations"] == [] and r["count"] == 0 for r in res)
    assert res[-1]["n_prior"] == 5


def test_first_events_have_zero_prior():
    res, _ = compute_uba(frame(make_user_csv()), min_history=3)
    assert res[0]["n_prior"] == 0 and res[0]["status"] == "insufficient_history"
    assert res[3]["n_prior"] == 3 and res[3]["status"] == "ok"


def test_no_future_leakage_truncation_does_not_change_earlier_results():
    full = frame(make_user_csv())
    k = 25
    part_res, _ = compute_uba(full.iloc[:k].reset_index(drop=True), 10)
    full_res, _ = compute_uba(full, 10)
    assert part_res == full_res[:k]


def test_no_future_leakage_changing_future_values_does_not_change_earlier_results():
    base = frame(make_user_csv())
    tampered = base.copy()
    tampered.loc[len(tampered) - 1, ["failed_attempts", "unique_ips_24h"]] = [999, 999]
    a, _ = compute_uba(base, 10)
    b, _ = compute_uba(tampered, 10)
    assert a[:-1] == b[:-1]


def test_events_are_ordered_by_timestamp_not_file_order():
    shuffled = frame(make_user_csv()).sample(frac=1.0, random_state=1).reset_index(drop=True)
    res, basis = compute_uba(shuffled, 10)
    spike = shuffled.index[shuffled["failed_attempts"] == 20][0]
    assert basis == "timestamp" and res[spike]["n_prior"] == 30 and res[spike]["count"] >= 4


def test_mixed_timezone_offsets_are_ordered_by_utc_instant():
    f = pd.DataFrame([
        {"username": "alice", "timestamp": "2023-12-31T23:00:00Z", "failed_attempts": 0,
         "login_hour": 1, "unique_ips_24h": 1, "new_device": 0, "country_changed": 0},
        {"username": "alice", "timestamp": "2024-01-01T00:30:00+02:00", "failed_attempts": 0,
         "login_hour": 1, "unique_ips_24h": 1, "new_device": 0, "country_changed": 0},
    ])

    result, basis = compute_uba(f, min_history=1)

    assert basis == "timestamp"
    assert [event["n_prior"] for event in result] == [1, 0]


def test_users_are_independent():
    both = pd.concat([frame(make_user_csv(user="alice")), frame(make_user_csv(spike=False, user="bob"))],
                     ignore_index=True)
    res, _ = compute_uba(both, 10)
    assert res[30]["count"] >= 4                  # alice's spike
    assert all(r["count"] == 0 for r in res[31:])  # bob unaffected by alice's data


def test_bad_timestamps_fall_back_to_row_order():
    f = frame(make_user_csv())
    f["timestamp"] = "not a date"
    _, basis = compute_uba(f, 10)
    assert basis == "row_order"


def test_profile_first_and_last_seen_compare_timestamps_by_instant():
    features = {"login_hour": 10, "failed_attempts": 0, "unique_ips_24h": 1,
                "new_device": 0, "country_changed": 0}
    events = [
        {"data": {**features, "timestamp": "2024-01-01T00:30:00+02:00"}},
        {"data": {**features, "timestamp": "2023-12-31T23:00:00Z"}},
    ]
    profile = user_profile(events, 10)
    assert profile["first_seen"] == "2023-12-31T22:30:00+00:00"
    assert profile["last_seen"] == "2023-12-31T23:00:00+00:00"


def test_missing_username_column_and_blank_usernames():
    f = frame(make_user_csv())
    res, basis = compute_uba(f.drop(columns=["username"]), 10)
    assert basis == "none" and {r["status"] for r in res} == {"unavailable"}
    f.loc[0, "username"] = "  "
    assert compute_uba(f, 10)[0][0]["status"] == "no_user"


def test_only_features_are_used_never_labels():
    f = frame(make_user_csv())
    f["label"] = 1
    assert "label" not in FEATURES
    assert compute_uba(f, 10)[0] == compute_uba(f.drop(columns=["label"]), 10)[0]


# ------------------------------------------------------------------ API
def test_api_uba_fields_and_min_history_param(client):
    sid = post_csv(client, make_user_csv(), uba_min_history=10).json()["scan_id"]
    d = client.get(f"/api/scans/{sid}/alerts", params={"detector": "either"}).json()["items"][0]
    detail = client.get(f"/api/scans/{sid}/alerts/{d['row']}").json()
    assert detail["uba"]["status"] == "ok" and detail["uba_deviations"] >= 4
    assert any(f["factor"] == "user_baseline" for f in detail["factors"])
    strict = post_csv(client, make_user_csv(), uba_min_history=50).json()
    assert strict["uba_min_history"] == 50
    assert post_csv(client, make_user_csv(), uba_min_history=1).status_code == 422


def test_api_users_and_profile(client, scan_id):
    users = client.get(f"/api/scans/{scan_id}/users", params={"page_size": 5}).json()
    assert users["total"] > 5 and len(users["items"]) == 5 and users["uba_basis"] == "timestamp"
    name = users["items"][0]["username"]
    p = client.get(f"/api/scans/{scan_id}/user-profile", params={"username": name}).json()
    assert p["username"] == name and len(p["profile"]["hour_histogram"]) == 24
    assert sum(p["profile"]["hour_histogram"]) == p["profile"]["events"]
    q = client.get(f"/api/scans/{scan_id}/users", params={"q": name[-3:]}).json()
    assert any(u["username"] == name for u in q["items"])


def test_api_profile_notice_for_insufficient_history(client):
    sid = post_csv(client, make_user_csv(n_stable=4)).json()["scan_id"]
    p = client.get(f"/api/scans/{sid}/user-profile", params={"username": "alice"}).json()
    assert "Insufficient history" in p["notice"] and p["deviation_events"] == []


def test_api_profile_404s(client, scan_id):
    assert client.get(f"/api/scans/{scan_id}/user-profile", params={"username": "ghost"}).status_code == 404
    assert client.get(f"/api/scans/{scan_id}/user-profile").status_code == 422
    assert client.get("/api/scans/nope/users").status_code == 404
