"""garak adapter: runs an approved garak probe in garak's own isolated venv, with garak's REST generator pointed at
AgentShield's gateway endpoint (POST /api/gateway/garak/{run_id}/{case_id}).

garak usage (garak 0.17.1, checked against the installed package and https://reference.garak.ai/en/latest/):
  python -m garak --config run.yaml --target_type rest --generator_option_file gen.json --spec probes.<probe>
                  [--detectors <detector>]
  run.yaml:  system.parallel_attempts: false · run.generations: 1 · run.soft_probe_prompt_cap: <case cap>
             reporting.report_dir / reporting.report_prefix  -> <report_dir>/<prefix>.report.jsonl
  gen.json:  {"rest": {"RestGenerator": {"uri", "method": "post", "headers", "req_template_json_object":
              {"prompt": "$INPUT"}, "response_json": true, "response_json_field": "text", "request_timeout",
              "skip_codes": [...], "ratelimit_codes": [429]}}}
  A response whose status is in skip_codes is recorded by garak as "no output" for that prompt and the run goes on;
  any other 4xx/5xx aborts the run. report.jsonl `attempt` rows with status 2 carry outputs + detector_results.

Every prompt garak sends arrives at the endpoint, which calls `CaseContext.invoke` (the gateway). The endpoint
accepts only loopback clients presenting the case's one-time bearer token, valid only while the case executes.
Gateway refusals answer 409 and target errors 424, both skip codes, so garak records the prompt as unanswered:
e.g. garak's test.Test sends 8 fixed prompts; with a 5-prompt technique budget 5 are answered and 3 are refused.

Verdict: garak detector score >= GARAK_FAIL_THRESHOLD on any scored reply -> fail (a candidate finding: a detector
hit is not a confirmed exploit); otherwise pass when at least one reply was scored; inconclusive when none was.
report.jsonl and garak's log are stored under EVIDENCE_DIR and hashed.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import subprocess
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from ..config import get_settings
from ..gateway import GatewayRefused
from ..ingest import garak as garak_parser
from ..redact import redact_text
from ..safety import KILL
from .engines import status as engine_status
from .orchestrator import STOP_CODES, CaseContext, CaseResult

REFUSED, TARGET_ERROR = 409, 424
LOOPBACK = {"127.0.0.1", "::1", "localhost"}


@dataclass
class GarakSession:
    token: str
    ctx: CaseContext
    seq: int = 0
    answered: int = 0
    target_errors: int = 0
    refusals: Counter = field(default_factory=Counter)
    stop: GatewayRefused | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)


_sessions: dict[tuple[str, str], GarakSession] = {}
_sessions_lock = threading.Lock()


def handle_prompt(run_id: str, case_id: str, token: str, client_host: str, prompt: str) -> tuple[int, dict]:
    """Called by the API endpoint for each prompt garak sends. Returns (HTTP status, JSON body)."""
    if client_host not in LOOPBACK:
        return 403, {"detail": "The garak gateway endpoint accepts loopback clients only."}
    with _sessions_lock:
        sess = _sessions.get((run_id, case_id))
    if sess is None or not hmac.compare_digest(sess.token, token or ""):
        return 403, {"detail": "No garak case is executing for this run/case, or the token is wrong."}
    with sess.lock:
        sess.seq += 1
        n = sess.seq
        stopped = sess.stop
    if stopped is not None:
        sess.refusals[stopped.code] += 1
        return REFUSED, {"refused": stopped.code, "detail": stopped.message}
    try:
        # One garak prompt = one isolated conversation (garak attempts are independent).
        res = sess.ctx.invoke(prompt, turn=1, test_key=f"{case_id}#{n}")
    except GatewayRefused as e:
        with sess.lock:
            sess.refusals[e.code] += 1
            if e.code in STOP_CODES and sess.stop is None:
                sess.stop = e
        return REFUSED, {"refused": e.code, "detail": e.message}
    if res.status != "ok":
        with sess.lock:
            sess.target_errors += 1
        return TARGET_ERROR, {"error": res.error_code or "error", "detail": res.error}
    with sess.lock:
        sess.answered += 1
    return 200, {"text": res.text}


def _base_url() -> str:
    st = get_settings()
    return (st.gateway_public_url or f"http://127.0.0.1:{st.port}").rstrip("/")


def _child_env(folder: Path) -> dict:
    """garak gets a minimal environment: no AgentShield API keys or cloud credentials, and its own XDG dirs."""
    keep = {"SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "TEMP", "TMP", "PATH", "PATHEXT", "COMSPEC", "LANG", "LC_ALL",
            "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "HOME", "APPDATA", "LOCALAPPDATA", "NUMBER_OF_PROCESSORS"}
    env = {k: v for k, v in os.environ.items() if k.upper() in keep}
    for name in ("XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"):
        d = folder / "xdg" / name.split("_")[1].lower()
        d.mkdir(parents=True, exist_ok=True)
        env[name] = str(d)
    env["PYTHONIOENCODING"] = "utf-8"
    env["NO_PROXY"] = "127.0.0.1,localhost"
    return env


def _write_configs(ctx: CaseContext, folder: Path, token: str) -> tuple[Path, Path]:
    st = get_settings()
    case = ctx.case
    gen = {"rest": {"RestGenerator": {
        "name": "agentshield-gateway", "uri": f"{_base_url()}/api/gateway/garak/{ctx.run_id}/{case['id']}",
        "method": "post", "headers": {"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        "req_template_json_object": {"prompt": "$INPUT"}, "response_json": True, "response_json_field": "text",
        "request_timeout": int(ctx.plan["limits"].get("invocation_timeout_s", st.invocation_timeout_s)) + 30,
        "skip_codes": [REFUSED, TARGET_ERROR], "ratelimit_codes": [429]}}}
    gen_path = folder / "generator.json"
    gen_path.write_text(json.dumps(gen, indent=2), encoding="utf-8")
    cfg = (f"system:\n  parallel_attempts: false\n  lite: true\n  narrow_output: true\n"
           f"run:\n  generations: 1\n  soft_probe_prompt_cap: {int(case['prompt_cap'])}\n"
           f"reporting:\n  report_dir: {json.dumps(folder.as_posix())}\n  report_prefix: garak\n")
    cfg_path = folder / "run.yaml"
    cfg_path.write_text(cfg, encoding="utf-8")
    return cfg_path, gen_path


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else ""


def run_case(ctx: CaseContext) -> CaseResult:
    st = get_settings()
    case = ctx.case
    python = st.garak_python_path
    version = engine_status()["garak"]["version"]
    if not python.exists():
        return CaseResult(verdict="error", source_verdict="", test_id=f"probes.{case['probe']}",
                          error=f"garak venv not found at {python}", engine_version=version)
    folder = Path(st.evidence_dir) / ctx.run_id / f"{case['id']}-garak"
    folder.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(32)
    cfg_path, gen_path = _write_configs(ctx, folder, token)
    cmd = [str(python), "-m", "garak", "--config", str(cfg_path), "--target_type", "rest",
           "--generator_option_file", str(gen_path), "--spec", f"probes.{case['probe']}"]
    if case.get("detector"):
        cmd += ["--detectors", case["detector"]]
    sess = GarakSession(token=token, ctx=ctx)
    with _sessions_lock:
        _sessions[(ctx.run_id, case["id"])] = sess
    log_path = folder / "garak.stdout.log"
    timed_out = abandoned = False
    try:
        with open(log_path, "wb") as log_file:
            proc = subprocess.Popen(cmd, stdout=log_file, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                    cwd=str(folder), env=_child_env(folder))
            deadline = time.monotonic() + st.garak_timeout_s
            while proc.poll() is None:
                if ctx.cancel.is_set() or KILL.tripped:
                    abandoned = True
                elif time.monotonic() > deadline:
                    timed_out = True
                if abandoned or timed_out:
                    proc.terminate()
                    try:
                        proc.wait(5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(5)
                    break
                time.sleep(0.2)
            returncode = proc.returncode
    finally:
        with _sessions_lock:
            _sessions.pop((ctx.run_id, case["id"]), None)

    if sess.stop is not None:
        raise sess.stop  # cancelled / halted / run budget: the orchestrator stops the execution
    log_tail, _ = redact_text(log_path.read_text(encoding="utf-8", errors="replace")[-1500:] if log_path.exists() else "")
    report = folder / "garak.report.jsonl"
    common = {"engine_version": version, "strategy": f"garak probes.{case['probe']}",
              "test_id": f"probes.{case['probe']}", "detector": case.get("detector", "")}
    detail = {"probe": case["probe"], "detector": case.get("detector", ""), "prompt_cap": case["prompt_cap"],
              "prompts_seen": sess.seq, "prompts_answered": sess.answered, "target_errors": sess.target_errors,
              "refusals": dict(sess.refusals), "returncode": returncode, "command": cmd[1:]}
    evidence = {"file": str(report), "sha256": _sha(report), "log_file": str(log_path), "log_sha256": _sha(log_path),
                "format": "garak-report-jsonl"}
    if abandoned:
        return CaseResult(verdict="error", source_verdict="", error="garak run abandoned: execution stopped",
                          source_detail=detail, evidence=evidence, **common)
    if timed_out:
        return CaseResult(verdict="error", source_verdict="", error=f"garak exceeded GARAK_TIMEOUT_S ({st.garak_timeout_s}s)",
                          source_detail=detail | {"log_tail": log_tail}, evidence=evidence, **common)
    if returncode != 0 or not report.exists():
        return CaseResult(verdict="error", source_verdict="", error=f"garak exited with code {returncode}",
                          source_detail=detail | {"log_tail": log_tail}, evidence=evidence, **common)

    parsed = garak_parser.parse(report.read_text(encoding="utf-8", errors="replace").splitlines(),
                                fail_threshold=st.garak_fail_threshold)
    scored = [a for a in parsed.attempts if a.score is not None]
    failed = [a for a in scored if a.verdict == "fail"]
    best = max(scored, key=lambda a: a.score, default=None)
    verdict = "fail" if failed else "pass" if scored else "inconclusive"
    unanswered = len(parsed.attempts) - len(scored)
    refused_txt = ", ".join(f"{k} x{v}" for k, v in sorted(sess.refusals.items()))
    rationale = (f"garak {case['probe']}: {len(scored)} repl{'y' if len(scored) == 1 else 'ies'} scored by "
                 f"{best.detector if best else case.get('detector') or 'the probe detector'}, {len(failed)} at or above "
                 f"{st.garak_fail_threshold}" + (f" (max {best.score:.2f})" if best else "") +
                 (f"; {unanswered} prompt(s) unanswered" if unanswered else "") +
                 (f"; gateway refused {refused_txt}" if refused_txt else "") +
                 (f"; {sess.target_errors} target error(s)" if sess.target_errors else "") + ".")
    turns = []
    for a in parsed.attempts:
        for t in a.turns:
            text, _ = redact_text(t.get("text", ""))
            turns.append({"role": t.get("role", "user"), "text": text} | (
                {"generation": t["generation"]} if "generation" in t else {}))
    detail["attempts"] = [{"uuid": a.external_id, "detector": a.detector, "score": a.score, "verdict": a.verdict}
                          for a in parsed.attempts][:200]
    detail["garak_version"] = parsed.tool_version or version
    return CaseResult(verdict=verdict, source_verdict=f"max detector score {best.score:.2f}" if best else "no scored output",
                      score=best.score if best else None, rationale=rationale, turns=turns[:400],
                      source_detail=detail, evidence=evidence, **(common | {"detector": best.detector if best else common["detector"]}))
