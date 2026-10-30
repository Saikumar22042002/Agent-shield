"""Credential redaction for everything the gateway persists, audits or publishes.

Applied to prompts, replies, provider error text and tool-event payloads before they reach SQLite, the audit
chain or the live stream. Patterns cover credential shapes that can plausibly appear in agent traffic; the
configured API keys are also redacted verbatim. Redaction is lossy by design: the original is never stored.
"""
from __future__ import annotations

import re
from typing import Any

from .config import get_settings

MASK = "[REDACTED:{kind}]"

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b")),
    ("aws-secret", re.compile(r"(?i)(aws_secret_access_key|secretaccesskey)(\s*[:=]\s*[\"']?)[A-Za-z0-9/+]{40}")),
    ("aws-session-token", re.compile(r"(?i)(aws_session_token|sessiontoken)(\s*[:=]\s*[\"']?)[A-Za-z0-9/+=]{100,}")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----")),
    ("bearer", re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9\-._~+/]{20,}=*")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("api-key", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|gsk_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35}|xox[abposr]-[A-Za-z0-9-]{10,}|gh[pousr]_[A-Za-z0-9]{36,})\b")),
    ("password", re.compile(r"(?i)\b(password|passwd|pwd|api[_-]?key|secret|token)(\s*[:=]\s*)([\"']?)[^\s\"',;]{6,}")),
]


def _configured_secrets() -> list[str]:
    st = get_settings()
    return [v for v in (st.google_api_key, st.groq_api_key) if v and len(v) >= 8]


def redact_text(text: str) -> tuple[str, int]:
    """(redacted text, number of replacements)."""
    if not text:
        return text, 0
    n = 0
    for secret in _configured_secrets():
        if secret in text:
            n += text.count(secret)
            text = text.replace(secret, MASK.format(kind="configured-key"))
    for kind, pat in PATTERNS:
        def sub(m: re.Match[str], kind=kind) -> str:
            nonlocal n
            n += 1
            # keep the label for key=value shapes so the evidence stays readable
            if kind in ("aws-secret", "aws-session-token") or (kind == "password"):
                return f"{m.group(1)}{m.group(2)}{MASK.format(kind=kind)}"
            if kind == "bearer":
                return f"{m.group(1)} {MASK.format(kind=kind)}"
            return MASK.format(kind=kind)
        text = pat.sub(sub, text)
    return text, n


def redact(value: Any) -> tuple[Any, int]:
    """Recursively redact strings inside dicts/lists. Returns (value, replacements)."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        total, out = 0, {}
        for k, v in value.items():
            out[k], n = redact(v)
            total += n
        return out, total
    if isinstance(value, list):
        total, items = 0, []
        for v in value:
            r, n = redact(v)
            items.append(r)
            total += n
        return items, total
    return value, 0
