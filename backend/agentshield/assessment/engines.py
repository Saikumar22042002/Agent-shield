"""Which execution frameworks are installed and usable, with exact versions.

PyRIT and deepagents live in the API's own venv. garak lives in an isolated venv (backend/.venv-garak) because its
pinned dependencies conflict with PyRIT's; it is executed as a subprocess and reaches targets only through the
gateway's REST endpoint.
"""
from __future__ import annotations

import importlib.metadata as md
import importlib.util
from functools import lru_cache
from pathlib import Path

from ..config import get_settings


def _dist_version(name: str) -> str:
    try:
        return md.version(name)
    except md.PackageNotFoundError:
        return ""


@lru_cache
def _garak_version(python: str) -> str:
    """Read the version from the garak venv's dist-info (no subprocess, so the API starts fast)."""
    exe = Path(python)
    if not exe.exists():
        return ""
    root = exe.parent.parent  # <venv>/Scripts/python.exe or <venv>/bin/python
    for site in (root / "Lib" / "site-packages", *root.glob("lib/python3*/site-packages")):
        for d in site.glob("garak-*.dist-info"):
            return d.name.removeprefix("garak-").removesuffix(".dist-info")
    return ""


def coordinator_mode() -> str:
    st = get_settings()
    mode = (st.coordinator_model or "deterministic").strip().lower()
    usable = bool(st.generation_model and st.api_key_for(st.generation_model))
    if mode == "llm" or (mode == "auto" and usable):
        return f"LLM ({st.generation_model or 'GENERATION_MODEL unset'})"
    return "deterministic (scripted rules, no LLM)"


def status() -> dict[str, dict]:
    st = get_settings()
    pyrit_v = _dist_version("pyrit") if importlib.util.find_spec("pyrit") else ""
    garak_py = st.garak_python_path
    garak_v = _garak_version(str(garak_py))
    da_v = _dist_version("deepagents")
    return {
        "pyrit": {"available": bool(pyrit_v), "version": pyrit_v, "label": "PyRIT",
                  "detail": "In-process. Attacks run against a PromptTarget whose only transport is the gateway."
                  if pyrit_v else "pyrit is not installed in the API venv."},
        "garak": {"available": bool(garak_v), "version": garak_v, "label": "garak",
                  "detail": (f"Subprocess in {garak_py.parent.parent.name}; REST generator posts to the gateway."
                             if garak_v else f"garak venv not found at {garak_py}."), "python": str(garak_py)},
        "deepagents": {"available": bool(da_v), "version": da_v, "label": "LangChain Deep Agents",
                       "detail": "Run coordinator (supervisor + evidence-analyst and reporter subagents). Tools: list, "
                                 "execute, skip approved cases, read evidence, stop. Chat model: "
                                 f"{coordinator_mode()}."},
    }
