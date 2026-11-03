"""Optional Gemini narrative for reports. The offline template remains complete without it."""
from __future__ import annotations

import json
import logging
import os
import socket
import urllib.error
import urllib.parse
import urllib.request

log = logging.getLogger(__name__)
API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
DEFAULT_MODEL = "gemini-3.5-flash-lite"
DEFAULT_TIMEOUT = 60.0
SYSTEM = (
    "You write a short plain-language summary for a security analyst. Use ONLY the facts provided. "
    "Do not add, infer or speculate about any fact, cause, attacker, or impact. State uncertainty. "
    "Anomaly flags are not proof of an attack. Do not recommend automatic remediation."
)


def _api_key() -> str | None:
    # Whitespace around clipboard input is harmless; internal whitespace can
    # never form a valid header value and is rejected before urllib sees it.
    key = os.getenv("GEMINI_API_KEY", "").strip()
    return key if key and not any(ch.isspace() for ch in key) else None


def available() -> bool:
    return os.getenv("SAD_LLM_ENABLED") == "1" and _api_key() is not None


def model_name() -> str:
    return os.getenv("SAD_LLM_MODEL") or DEFAULT_MODEL


def timeout_seconds() -> float:
    try:
        value = float(os.getenv("SAD_LLM_TIMEOUT", str(DEFAULT_TIMEOUT)))
    except (TypeError, ValueError):
        value = DEFAULT_TIMEOUT
    return min(300.0, max(10.0, value))


def complete_with_reason(facts: str, system: str | None = None) -> tuple[str | None, str]:
    """Return model text and a safe fallback reason code; never log request or response data."""
    if os.getenv("SAD_LLM_ENABLED") != "1":
        return None, "disabled"
    key = _api_key()
    if key is None:
        return None, "disabled"

    model = urllib.parse.quote(model_name(), safe="-._")
    body = json.dumps({
        "systemInstruction": {"parts": [{"text": system or SYSTEM}]},
        "contents": [{"role": "user", "parts": [{"text": facts}]}],
        "generationConfig": {"maxOutputTokens": 2048},
    }).encode()
    req = urllib.request.Request(API_URL.format(model=model), data=body, method="POST", headers={
        "content-type": "application/json", "x-goog-api-key": key,
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds()) as resp:  # noqa: S310 - fixed https URL
            data = json.load(resp)
    except urllib.error.HTTPError as exc:
        reason = f"http_{exc.code}"
    except (TimeoutError, socket.timeout):
        reason = "timeout"
    except urllib.error.URLError as exc:
        reason = "timeout" if isinstance(exc.reason, (TimeoutError, socket.timeout)) else "network"
    except OSError:
        reason = "network"
    except (json.JSONDecodeError, UnicodeDecodeError):
        reason = "bad_json"
    except Exception:
        reason = "network"
    else:
        if not isinstance(data, dict) or not isinstance(data.get("candidates", []), list):
            reason = "bad_json"
        else:
            candidates = data.get("candidates", [])
            if any(isinstance(c, dict) and c.get("finishReason") == "MAX_TOKENS" for c in candidates):
                reason = "max_tokens"
            else:
                parts = [
                    part["text"]
                    for candidate in candidates if isinstance(candidate, dict)
                    for content in [candidate.get("content", {})]
                    if isinstance(content, dict)
                    for part in content.get("parts", []) if isinstance(part, dict)
                    and isinstance(part.get("text"), str)
                ]
                text = "".join(parts).strip()
                if text:
                    return text, ""
                reason = "empty_response"

    # Log only a fixed reason code, which includes the HTTP status when relevant.
    log.warning("LLM summary unavailable: %s", reason)
    return None, reason


def complete(facts: str) -> str | None:
    """Compatibility helper returning text only; callers can use the reason-aware variant."""
    return complete_with_reason(facts)[0]
