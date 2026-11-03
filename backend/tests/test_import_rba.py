"""Importer for the RBA login dataset, tested on a file in the real dataset's exact format."""
import csv
import random

import pandas as pd
import pytest

from scripts import import_rba

from .conftest import post_csv

HEADER = ["index", "Login Timestamp", "User ID", "Round-Trip Time [ms]", "IP Address", "Country", "Region", "City",
          "ASN", "User Agent String", "Browser Name and Version", "OS Name and Version", "Device Type",
          "Login Successful", "Is Attack IP", "Is Account Takeover"]
UA = "Mozilla/5.0  (iPhone; CPU iPhone OS 13_4 like Mac OS X) Gecko/20150101 Firefox/20.0.0.1618 (Chrome variation/248113"


def write_rba(path, rows):
    """rows: (user, 'YYYY-mm-dd HH:MM:SS', ip, country, browser, os, device, success, attack_ip, takeover)"""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(HEADER)
        for i, (u, t, ip, cty, br, os_, dev, ok, atk, ato) in enumerate(rows):
            w.writerow([i, t + ".123", u, "", ip, cty, "-", "-", 29695, UA + ",quoted, comma", br, os_, dev, ok, atk, ato])


def test_features_computed_causally_from_user_history(tmp_path):
    U = -4324475583306591935  # negative 64-bit ids exist in the real file
    rows = [
        (U, "2020-02-03 10:00:00", "1.1.1.1", "NO", "Chrome 80", "Windows 10", "desktop", True, False, False),
        (U, "2020-02-03 10:05:00", "1.1.1.1", "NO", "Chrome 80", "Windows 10", "desktop", False, False, False),
        (U, "2020-02-03 10:06:00", "2.2.2.2", "NO", "Chrome 80", "Windows 10", "desktop", False, False, False),
        (U, "2020-02-03 10:07:00", "3.3.3.3", "AU", "Firefox 70", "Linux", "desktop", True, True, True),
        (U, "2020-02-05 03:00:00", "1.1.1.1", "NO", "Chrome 80", "Windows 10", "desktop", True, False, False),
    ]
    src = tmp_path / "rba.csv"
    write_rba(src, rows)
    cols = import_rba.resolve_columns(list(pd.read_csv(src, nrows=0).columns))
    raw = import_rba.gather(src, cols, pd.Series([U]).to_numpy(), 2)
    out = import_rba.build_features(raw).reset_index(drop=True)

    assert list(out["failed_attempts"]) == [0, 1, 2, 2, 0]      # 24 h window; the last event is 2 days later
    assert list(out["unique_ips_24h"]) == [1, 1, 2, 3, 1]
    assert list(out["new_device"]) == [0, 0, 0, 1, 0]            # first event has no history; Firefox/Linux is new
    assert list(out["country_changed"]) == [0, 0, 0, 1, 1]       # NO -> AU, then AU -> NO
    assert list(out["login_hour"]) == [10, 10, 10, 10, 3]
    assert list(out["label"]) == [0, 0, 0, 1, 0]
    assert list(out["attack_type"]) == ["none", "none", "none", "account_takeover", "none"]
    assert out["username"].nunique() == 1 and out["username"][0].startswith("user_")


def _big_fake(path, seed=3, users=600):
    rng = random.Random(seed)
    rows, uid = [], 0
    for u in range(users):
        uid = (u * 7919 + 13) * (-1 if u % 3 == 0 else 1) * 10**12
        home = rng.choice(["NO", "SE", "DK"])
        for k in range(rng.randint(6, 30)):
            day, hour = rng.randint(1, 27), rng.choice([8, 9, 10, 17, 18, 21])
            rows.append((uid, f"2020-02-{day:02d} {hour:02d}:{rng.randint(0,59):02d}:00", f"10.{u % 250}.0.1", home,
                         "Chrome 80", "Windows 10", "desktop", rng.random() > 0.05, False, False))
    for a in range(60):  # attack-IP logins against otherwise normal users
        rows.append(((a * 7919 + 13) * 10**12, f"2020-02-10 03:{a % 60:02d}:00", f"185.0.{a}.9", "RU",
                     "Bot 1", "Linux", "desktop", False, True, False))
    for a in range(5):   # targeted takeovers
        rows.append((-(a * 31 + 5) * 10**12 - 1, f"2020-02-12 04:1{a}:00", f"185.1.{a}.9", "CN",
                     "Bot 2", "Linux", "desktop", True, True, True))
        rows.append((-(a * 31 + 5) * 10**12 - 1, f"2020-02-11 09:1{a}:00", "10.9.9.9", "NO",
                     "Chrome 80", "Windows 10", "desktop", True, False, False))
    rng.shuffle(rows)
    rows.sort(key=lambda r: r[1])
    write_rba(path, rows)


def test_end_to_end_multi_chunk_and_dashboard_accepts_output(tmp_path, client):
    src, out = tmp_path / "rba.csv", tmp_path / "sample.csv"
    _big_fake(src)
    feats = import_rba.run(src, out, max_rows=4000, positive_rate=0.05, chunk_rows=700)  # forces many chunks

    assert list(feats.columns)[:11] == ["event_id", "timestamp", "username", "source_ip", "failed_attempts",
                                       "login_hour", "unique_ips_24h", "new_device", "country_changed", "label",
                                       "attack_type"]
    assert 0 < len(feats) <= 4000
    assert (feats["attack_type"] == "account_takeover").sum() == 5          # every takeover is kept
    assert 0 < feats["label"].mean() <= 0.06                                 # attack share stays small
    assert out.stat().st_size < import_rba.MAX_DASHBOARD_BYTES
    assert feats["timestamp"].is_monotonic_increasing

    r = post_csv(client, out.read_text(), name="rba_sample.csv", mode="batch")  # the real upload path
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["rows_analyzed"] == len(feats) and body["evaluation"]["positives"] == int(feats["label"].sum())


def test_label_modes(tmp_path):
    src = tmp_path / "rba.csv"
    _big_fake(src)
    t = import_rba.run(src, tmp_path / "t.csv", label_mode="takeover", max_rows=4000, chunk_rows=900)
    assert set(t.loc[t["label"] == 1, "attack_type"]) == {"account_takeover"}
    a = import_rba.run(src, tmp_path / "a.csv", label_mode="attack_ip", max_rows=4000, chunk_rows=900)
    assert a["label"].sum() > 0
    assert a.loc[a["label"] == 1, "attack_type"].isin(["attack_ip", "account_takeover"]).all()
    assert not (a.loc[a["label"] == 0, "attack_type"] == "attack_ip").any()


def test_deterministic_for_same_seed(tmp_path):
    src = tmp_path / "rba.csv"
    _big_fake(src)
    a = import_rba.run(src, tmp_path / "a.csv", max_rows=3000, seed=5, chunk_rows=800)
    b = import_rba.run(src, tmp_path / "b.csv", max_rows=3000, seed=5, chunk_rows=1500)
    pd.testing.assert_frame_equal(a, b)


def test_missing_columns_give_a_clear_error(tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text("a,b,c\n1,2,3\n")
    with pytest.raises(SystemExit) as e:
        import_rba.resolve_columns(list(pd.read_csv(bad, nrows=0).columns))
    assert "Could not find these columns" in str(e.value) and "login timestamp" in str(e.value)


def test_no_positives_is_reported(tmp_path):
    src = tmp_path / "rba.csv"
    write_rba(src, [(1, "2020-02-01 10:00:00", "1.1.1.1", "NO", "C", "W", "d", True, False, False)] * 8)
    with pytest.raises(SystemExit) as e:
        import_rba.run(src, tmp_path / "o.csv")
    assert "No positive events" in str(e.value)


def test_header_spelling_is_flexible(tmp_path):
    cols = import_rba.resolve_columns([h.upper() for h in HEADER])
    assert cols["takeover"] == "IS ACCOUNT TAKEOVER" and cols["user"] == "USER ID"
