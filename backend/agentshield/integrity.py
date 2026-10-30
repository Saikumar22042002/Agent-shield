"""Hashes that tie an approved plan to what it was approved against.

A plan records the sha256 of the target profile and of the technique catalog it was built from. Approval is only
valid while both still match: the orchestrator refuses to start and the gateway refuses every call otherwise
(`plan_stale`), so a changed profile or catalog always needs a new plan and a new approval.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .config import get_settings


def plan_sha(content: dict) -> str:
    return hashlib.sha256(json.dumps(content, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def profile_sha(raw_profile: dict | None) -> str:
    """sha256 of the validated profile, so equivalent JSON (key order, defaults) hashes the same."""
    from .profile import load

    return hashlib.sha256(load(raw_profile).model_dump_json().encode()).hexdigest()


def catalog_sha() -> str:
    return hashlib.sha256(Path(get_settings().technique_catalog_file).read_bytes()).hexdigest()


def staleness(content: dict, raw_profile: dict | None) -> str:
    """Why an approved plan no longer applies ("" when it still does)."""
    reasons = []
    if content.get("profile_sha256") and content["profile_sha256"] != profile_sha(raw_profile):
        reasons.append("the target profile changed after the plan was built")
    if content.get("catalog_sha256") and content["catalog_sha256"] != catalog_sha():
        reasons.append("the technique catalog changed after the plan was built")
    return "; ".join(reasons)
