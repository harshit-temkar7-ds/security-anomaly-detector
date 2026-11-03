"""Plain-English alert search.

A small, deterministic parser turns text such as
    "critical alerts at night with a new device for user_044"
into explicit filters. It is intentionally NOT an LLM: every filter is shown back to the
analyst as "interpreted as ...", results are reproducible, and nothing leaves the machine.
Anything the parser does not understand is reported, never guessed.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from . import service
from .config import STATUSES

MAX_LIMIT = 100
DEFAULT_LIMIT = 25

_NUM = r"(\d{1,3})"
_SEVERITIES = ("critical", "high", "medium", "low")


def _first(patterns: list[str], text: str) -> Optional[re.Match]:
    for p in patterns:
        m = re.search(p, text)
        if m:
            return m
    return None


def parse_query(text: str) -> dict[str, Any]:
    """Return {'filters': {...}, 'interpreted': [...]}; unknown filters are simply absent."""
    t = " " + re.sub(r"\s+", " ", text.lower().strip()) + " "
    f: dict[str, Any] = {}
    said: list[str] = []

    for sev in _SEVERITIES:
        if re.search(rf"\b{sev}\b", t) and not re.search(rf"\b{sev} (?:risk )?(?:users?|ips?)\b", t):
            f["severity"] = sev
            said.append(f"severity = {sev}")
            break

    # --- hours -------------------------------------------------------------
    m = _first([rf"between {_NUM}\s*(?:h|:00)?\s*(?:and|to|-)\s*{_NUM}\b",
                rf"\bhours? {_NUM}\s*(?:-|to)\s*{_NUM}\b"], t)
    if m and int(m.group(1)) <= int(m.group(2)) <= 23:
        f["hour_min"], f["hour_max"] = int(m.group(1)), int(m.group(2))
    elif re.search(r"\b(night|nights|overnight|early hours|early morning|after midnight|midnight)\b", t):
        f["hour_min"], f["hour_max"] = 0, 5
    elif re.search(r"\b(evening|late)\b", t):
        f["hour_min"], f["hour_max"] = 18, 23
    elif re.search(r"\bmorning\b", t):
        f["hour_min"], f["hour_max"] = 6, 11
    else:
        m = _first([rf"\bat {_NUM}\s*(am|pm)\b", rf"\b{_NUM}\s*(am|pm)\b"], t)
        if m and 1 <= int(m.group(1)) <= 12:
            h = int(m.group(1)) % 12 + (12 if m.group(2) == "pm" else 0)
            f["hour_min"] = f["hour_max"] = h
        else:
            m = re.search(rf"\b(?:hour|at hour) {_NUM}\b", t)
            if m and int(m.group(1)) <= 23:
                f["hour_min"] = f["hour_max"] = int(m.group(1))
    if "hour_min" in f:
        said.append(f"login hour {f['hour_min']:02d}:00-{f['hour_max']:02d}:59")

    # --- device / location --------------------------------------------------
    if re.search(r"\b(new|unknown|unrecognised|unrecognized) devices?\b", t):
        f["new_device"] = 1
        said.append("new_device = 1")
    if re.search(r"\b(country changed|changed country|new country|different country|new location|"
                 r"location change[d]?|changed location|travel(?:l)?ing|abroad|foreign)\b", t):
        f["country_changed"] = 1
        said.append("country_changed = 1")

    # --- counts -------------------------------------------------------------
    m = _first([rf"(?:at least|{_NUM}\+|>=)\s*{_NUM}?\s*(?:failed|failures?|failed attempts)",
                rf"(?:more than|over|>)\s*{_NUM}\s*(?:failed|failures?|failed attempts)",
                rf"{_NUM}\s*or more\s*(?:failed|failures?)",
                rf"failed(?: attempts?)?\s*(?:>=|>|over|above|at least)\s*{_NUM}"], t)
    if m:
        nums = [int(g) for g in m.groups() if g and g.isdigit()]
        if nums:
            strict = bool(re.search(r"more than|over|>(?!=)|above", m.group(0))) and "at least" not in m.group(0)
            f["failed_min"] = nums[-1] + (1 if strict else 0)
    elif re.search(r"\b(many|multiple|lots of|repeated|high number of) (?:failed|failures)\b", t) or \
            re.search(r"\bbrute[ -]?force\b", t):
        f["failed_min"] = 5 if "brute" not in t else 8
    if "failed_min" in f:
        said.append(f"failed_attempts >= {f['failed_min']}")

    m = _first([rf"(?:more than|over|>)\s*{_NUM}\s*(?:ips?|ip addresses|source ips)",
                rf"(?:at least|{_NUM}\+)\s*{_NUM}?\s*(?:ips?|ip addresses|source ips)",
                rf"{_NUM}\s*or more\s*(?:ips?|ip addresses)"], t)
    if m:
        nums = [int(g) for g in m.groups() if g and g.isdigit()]
        if nums:
            strict = bool(re.search(r"more than|over|>", m.group(0))) and "at least" not in m.group(0)
            f["ips_min"] = nums[-1] + (1 if strict else 0)
    elif re.search(r"\b(many|multiple|several|lots of) (?:different |source |distinct )?(?:ips?|ip addresses)\b", t) \
            or re.search(r"\bcredential stuffing\b", t):
        f["ips_min"] = 4
    if "ips_min" in f:
        said.append(f"unique_ips_24h >= {f['ips_min']}")

    # --- who / status / detector -------------------------------------------
    m = re.search(r"\b(user[_-]?\w+)\b", t)
    if m and m.group(1) not in ("users", "user"):
        f["username"] = m.group(1).replace("-", "_")
        said.append(f"username = {f['username']}")

    for st in STATUSES:
        words = st.replace("_", " ")
        if re.search(rf"\b{words}\b", t) and not (st == "new" and re.search(r"\bnew (?:device|country|location)", t)):
            if st == "new" and not re.search(r"\b(status new|unreviewed|untriaged|not reviewed)\b", t):
                continue
            f["status"] = st
            said.append(f"status = {words}")
            break
    if "status" not in f and re.search(r"\b(unreviewed|untriaged|not yet reviewed|not reviewed)\b", t):
        f["status"] = "new"
        said.append("status = new")
    if re.search(r"\b(false positives?)\b", t) and "status" not in f:
        f["status"] = "false_positive"
        said.append("status = false positive")

    if re.search(r"\b(rule|rules|rule[- ]based|rule baseline)\b", t) and not re.search(r"\bisolation\b|\bmodel\b", t):
        f["detector"] = "rules"
        said.append("detector = rule baseline")
    elif re.search(r"\b(model|isolation forest|ml)\b", t) and not re.search(r"\brule", t):
        f["detector"] = "model"
        said.append("detector = Isolation Forest")

    m = re.search(r"\b(?:top|first|latest|limit)\s*(\d{1,6})\b", t)
    if m:
        f["limit"] = max(1, min(MAX_LIMIT, int(m.group(1))))
        said.append(f"limit {f['limit']}")
    return {"filters": f, "interpreted": said}


def _matches(item: dict[str, Any], f: dict[str, Any]) -> bool:
    d = item["data"]
    if "hour_min" in f and not (f["hour_min"] <= int(d["login_hour"]) <= f["hour_max"]):
        return False
    if f.get("new_device") and int(d["new_device"]) != 1:
        return False
    if f.get("country_changed") and int(d["country_changed"]) != 1:
        return False
    if "failed_min" in f and int(d["failed_attempts"]) < f["failed_min"]:
        return False
    if "ips_min" in f and int(d["unique_ips_24h"]) < f["ips_min"]:
        return False
    return True


def search(scan: dict, text: str) -> dict[str, Any]:
    parsed = parse_query(text)
    f = parsed["filters"]
    # username match is case-insensitive here; list_alerts needs the stored spelling.
    username = None
    if "username" in f:
        users = service.list_users(scan, f["username"], 1, 100)["items"]
        exact = [u["username"] for u in users if u["username"].lower() == f["username"]]
        username = exact[0] if exact else f["username"]
    page = service.list_alerts(scan, f.get("detector", "either"), f.get("severity"), f.get("status"),
                               username, None, 1, 100_000)
    items = [i for i in page["items"] if _matches(i, f)]
    limit = f.get("limit", DEFAULT_LIMIT)
    return {
        "query": text, "interpreted": parsed["interpreted"], "understood": bool(parsed["interpreted"]),
        "total": len(items), "shown": min(len(items), limit), "items": items[:limit],
        "note": ("Search runs on flagged events only (model or rule baseline). Filters are shown above so "
                 "you can check how your words were interpreted."),
    }
