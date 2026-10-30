"""Local model target: a model served on this machine behind an OpenAI-compatible chat-completions API
(Ollama, LM Studio, llama.cpp server, vLLM).

  POST {base_url}/chat/completions  {"model": ..., "messages": [{"role", "content"}, ...], "stream": false}
  -> {"choices": [{"message": {"content": ...}, "finish_reason": ...}], "usage": {"prompt_tokens",
      "completion_tokens", "total_tokens"}}

Only loopback URLs are accepted (validated at registration and again here), so this provider can never reach a
remote service. The endpoint is stateless, so the connector keeps each session's history in process memory and sends
it with every turn: a session id is one isolated conversation, exactly like an agent session. Usage comes from the
server's `usage` object when it reports one (mapped to inputTokens / outputTokens / totalTokens); no service latency
is reported, so only the measured round trip is recorded.

Target.config: base_url (e.g. http://127.0.0.1:11434/v1), model, optional system_prompt, optional temperature.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
import uuid
from urllib.parse import urlparse

from ..audit import record as audit
from .base import ConnectorError, ConnectorInput, ConnectorOutput

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
MAX_HISTORY = 40

_histories: dict[str, list[dict]] = {}
_lock = threading.Lock()


def validate_base_url(url: str) -> str:
    """Normalised base URL, or ValueError when it is not an http(s) loopback URL."""
    u = urlparse((url or "").strip())
    if u.scheme not in ("http", "https") or (u.hostname or "") not in LOOPBACK_HOSTS:
        raise ValueError("base_url must be an http(s) URL on this machine (127.0.0.1, localhost or ::1), "
                         "e.g. http://127.0.0.1:11434/v1.")
    return url.strip().rstrip("/")


class LocalModelConnector:
    def __init__(self, *, config: dict, timeout_s: int = 120, run_id: str | None = None,
                 target_id: int | None = None, **_kw):
        self.base_url = validate_base_url(config.get("base_url", ""))
        self.model = str(config.get("model", "")).strip()
        if not self.model:
            raise ConnectorError("ValidationError", "Local model target has no model name configured.")
        self.system_prompt = str(config.get("system_prompt", "") or "")
        try:
            self.temperature = float(config["temperature"]) if str(config.get("temperature", "")).strip() else None
        except ValueError:
            self.temperature = None
        self.timeout_s, self.run_id, self.target_id = timeout_s, run_id, target_id

    def new_session_id(self) -> str:
        return f"agentshield-local-{uuid.uuid4()}"

    def send(self, inp: ConnectorInput) -> ConnectorOutput:
        with _lock:
            history = list(_histories.get(inp.session_id, []))
        messages = ([{"role": "system", "content": self.system_prompt}] if self.system_prompt else []) + history + [
            {"role": "user", "content": inp.text}]
        body = {"model": self.model, "messages": messages, "stream": False}
        if self.temperature is not None:
            body["temperature"] = self.temperature
        audit("connector.request", {"provider": "local_model", "url": f"{self.base_url}/chat/completions",
                                    "model": self.model, "session": inp.session_id, "text": inp.text,
                                    "history_messages": len(history)}, run_id=self.run_id, target_id=self.target_id)
        req = urllib.request.Request(f"{self.base_url}/chat/completions", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:  # noqa: S310 (loopback only)
                payload = json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")[:500]
            err = ConnectorError(f"HTTP{e.code}", detail or e.reason, retryable=e.code == 429 or e.code >= 500,
                                 hint="The local model server rejected the request; check the model name.")
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            err = ConnectorError("LocalModelUnreachable", str(getattr(e, "reason", e)), retryable=True,
                                 hint=f"Nothing answered at {self.base_url}. Start the local model server.")
        except json.JSONDecodeError as e:
            err = ConnectorError("BadResponse", f"Not JSON: {e}")
        else:
            wall = (time.perf_counter() - t0) * 1000
            try:
                choice = payload["choices"][0]
                text = choice["message"].get("content") or ""
            except (KeyError, IndexError, TypeError, AttributeError):
                err = ConnectorError("BadResponse", "Response has no choices[0].message.content.")
            else:
                u = payload.get("usage") or {}
                usage = {k: int(u[src]) for k, src in (("inputTokens", "prompt_tokens"), ("outputTokens",
                         "completion_tokens"), ("totalTokens", "total_tokens")) if isinstance(u.get(src), int)}
                with _lock:
                    h = _histories.setdefault(inp.session_id, [])
                    h += [{"role": "user", "content": inp.text}, {"role": "assistant", "content": text}]
                    del h[:-MAX_HISTORY]
                out = ConnectorOutput(text=text, session_id=inp.session_id, latency_ms=None, wall_ms=wall,
                                      usage=usage, stop_reason=str(choice.get("finish_reason") or ""))
                audit("connector.response", {"provider": "local_model", "session": inp.session_id, "text": text,
                                             "usage": usage, "wallMs": wall, "stopReason": out.stop_reason},
                      run_id=self.run_id, target_id=self.target_id)
                return out
        audit("connector.error", {"provider": "local_model", "session": inp.session_id, "code": err.code,
                                  "message": err.message}, run_id=self.run_id, target_id=self.target_id)
        raise err
