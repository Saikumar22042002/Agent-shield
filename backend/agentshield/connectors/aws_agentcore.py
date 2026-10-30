"""AWS Bedrock AgentCore connector — InvokeHarness.

Doc-verified (2026-10-29):
  API ref:  https://docs.aws.amazon.com/bedrock-agentcore/latest/APIReference/API_InvokeHarness.html
  boto3:    https://docs.aws.amazon.com/boto3/latest/reference/services/bedrock-agentcore/client/invoke_harness.html
  Dev guide https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness-get-started.html

  client = session.client("bedrock-agentcore")
  resp = client.invoke_harness(harnessArn=..., runtimeSessionId=<33..100 chars>,
                               messages=[{"role": "user", "content": [{"text": ...}]}], qualifier=?)
  for event in resp["stream"]:  # each event has exactly one key
      messageStart | contentBlockStart | contentBlockDelta{delta{text|toolUse|...}} | contentBlockStop
      messageStop{stopReason} | metadata{usage{inputTokens,outputTokens,totalTokens}, metrics{latencyMs}}
      hookEvent | internalServerException | validationException | runtimeClientError   (in-stream errors)
  Pre-stream errors: AccessDenied(403) ResourceNotFound(404) Validation(400) Throttling(429)
                     ServiceQuotaExceeded(402) RuntimeClientError(424) InternalServer(500)
  Requires boto3/botocore >= 1.43.99 for the full current shape.
"""
from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Iterable

from ..audit import record as audit
from .base import ConnectorError, ConnectorInput, ConnectorOutput

log = logging.getLogger(__name__)

OPERATOR_MESSAGES = {
    "AccessDeniedException": "AWS denied the call. The profile/role needs bedrock-agentcore:InvokeHarness on this harness ARN.",
    "ResourceNotFoundException": "Harness ARN not found in this region. Check TARGET_HARNESS_ARN and TARGET_REGION.",
    "ThrottlingException": "AgentCore is throttling requests. AgentShield will back off; consider lowering the rate limit.",
    "ValidationException": "AgentCore rejected the request shape (check ARN format, qualifier, session id).",
    "ServiceQuotaExceededException": "An AgentCore service quota was exceeded for this account.",
    "RuntimeClientError": "The harness runtime returned an error while executing (check the agent's own logs).",
    "InternalServerException": "AgentCore internal error. Retrying with backoff.",
    # Credential problems surface from STS / the SDK before AgentCore is reached.
    "UnrecognizedClientException": "AWS did not recognise the access key. Refresh the credentials for this profile (aws configure / aws sso login).",
    "InvalidClientTokenId": "AWS rejected the security token. Refresh the credentials for this profile (aws configure / aws sso login).",
    "ExpiredTokenException": "The AWS session token has expired. Run `aws sso login` or refresh the profile's credentials.",
    "ExpiredToken": "The AWS session token has expired. Run `aws sso login` or refresh the profile's credentials.",
    "NoCredentialsError": "No AWS credentials were found. Set AWS_PROFILE, attach an instance role, or configure the default profile.",
    "ProfileNotFound": "The AWS profile named on this target does not exist in ~/.aws/config.",
}
RETRYABLE = {"ThrottlingException", "InternalServerException"}
STREAM_ERRORS = {"internalServerException": "InternalServerException",
                 "validationException": "ValidationException",
                 "runtimeClientError": "RuntimeClientError"}


TOKEN_HINT = ("AWS rejected the credentials themselves (invalid or expired token), before any IAM permission was checked. "
              "Refresh the credentials for this profile (aws sso login / aws configure), then confirm with aws sts get-caller-identity.")


def hint_for(code: str, message: str = "") -> str:
    """Operator guidance for an AWS error code (empty when there is none). The provider message refines it:
    AgentCore reports a bad or expired token as AccessDeniedException, which needs different action than a
    missing IAM permission."""
    m = message.lower()
    if code == "AccessDeniedException" and ("security token" in m or "expired" in m or "signature" in m):
        return TOKEN_HINT
    return OPERATOR_MESSAGES.get(code, "")


def assemble_stream(events: Iterable[dict], session_id: str, on_delta=None) -> ConnectorOutput:
    """Fold the InvokeHarness event stream into one reply. Pure function — unit tested.

    Text deltas are concatenated in arrival order across all assistant messages (a harness can
    emit several messageStop events when it calls tools). The last messageStop wins for stopReason;
    usage is summed across metadata events and latencyMs taken from the last one.
    """
    parts: list[str] = []
    usage: dict[str, int] = {}
    latency: float | None = None
    stop = ""
    tools: list[dict] = []
    for ev in events:
        if "contentBlockDelta" in ev:
            delta = ev["contentBlockDelta"].get("delta", {})
            if "text" in delta:
                parts.append(delta["text"])
                if on_delta:
                    on_delta(delta["text"])
            elif "toolUse" in delta:
                tools.append({"type": "toolUseInput", "index": ev["contentBlockDelta"].get("contentBlockIndex"),
                              "input": delta["toolUse"].get("input", "")})
        elif "contentBlockStart" in ev:
            start = ev["contentBlockStart"].get("start", {})
            if "toolUse" in start:
                tools.append({"type": "toolUse", **{k: start["toolUse"].get(k) for k in ("toolUseId", "name", "type", "serverName")}})
        elif "messageStop" in ev:
            stop = ev["messageStop"].get("stopReason", "")
        elif "metadata" in ev:
            md = ev["metadata"]
            for k, v in (md.get("usage") or {}).items():
                usage[k] = usage.get(k, 0) + int(v)
            if (md.get("metrics") or {}).get("latencyMs") is not None:
                latency = float(md["metrics"]["latencyMs"])
        elif "hookEvent" in ev:
            tools.append({"type": "hook", **ev["hookEvent"]})
        else:
            for key, code in STREAM_ERRORS.items():
                if key in ev:
                    raise ConnectorError(code, ev[key].get("message", "") or code, retryable=code in RETRYABLE,
                                         hint=OPERATOR_MESSAGES[code])
    return ConnectorOutput(text="".join(parts), session_id=session_id, latency_ms=latency,
                           usage=usage, stop_reason=stop, tool_events=tools)


class AgentCoreConnector:
    def __init__(self, harness_arn: str, region: str, *, profile: str = "", role_arn: str = "",
                 qualifier: str = "", timeout_s: int = 120, max_retries: int = 0,
                 run_id: str | None = None, target_id: int | None = None):
        self.harness_arn = harness_arn
        self.region = region
        self.qualifier = qualifier
        self.max_retries = max_retries
        self.run_id = run_id
        self.target_id = target_id
        self._on_delta = None
        self._client = self._make_client(profile, role_arn, timeout_s)

    def set_delta_handler(self, fn) -> None:
        self._on_delta = fn

    def _make_client(self, profile: str, role_arn: str, timeout_s: int):
        import boto3
        from botocore.config import Config

        # Credentials come from the named profile / instance role / env chain — never embedded.
        session = boto3.Session(profile_name=profile or None, region_name=self.region)
        if role_arn:
            creds = session.client("sts").assume_role(RoleArn=role_arn, RoleSessionName="agentshield")["Credentials"]
            session = boto3.Session(aws_access_key_id=creds["AccessKeyId"],
                                    aws_secret_access_key=creds["SecretAccessKey"],
                                    aws_session_token=creds["SessionToken"], region_name=self.region)
        cfg = Config(read_timeout=timeout_s, connect_timeout=10, retries={"max_attempts": 1, "mode": "standard"})
        return session.client("bedrock-agentcore", config=cfg)

    def new_session_id(self) -> str:
        return f"agentshield-{uuid.uuid4()}"  # 48 chars; API requires 33..100, [a-zA-Z0-9][a-zA-Z0-9-_]*

    def send(self, inp: ConnectorInput) -> ConnectorOutput:
        from botocore.exceptions import BotoCoreError, ClientError

        kwargs = {"harnessArn": self.harness_arn, "runtimeSessionId": inp.session_id,
                  "messages": [{"role": "user", "content": [{"text": inp.text}]}]}
        if self.qualifier:
            kwargs["qualifier"] = self.qualifier
        audit("connector.request", {"harnessArn": self.harness_arn, "session": inp.session_id, "text": inp.text},
              run_id=self.run_id, target_id=self.target_id)

        delay = 1.0
        for attempt in range(self.max_retries + 1):
            t0 = time.perf_counter()
            try:
                resp = self._client.invoke_harness(**kwargs)
                out = assemble_stream(resp["stream"], inp.session_id, on_delta=self._on_delta)
                out.wall_ms = (time.perf_counter() - t0) * 1000
                audit("connector.response", {"session": inp.session_id, "text": out.text, "usage": out.usage,
                                             "latencyMs": out.latency_ms, "wallMs": out.wall_ms,
                                             "stopReason": out.stop_reason, "toolEvents": out.tool_events},
                      run_id=self.run_id, target_id=self.target_id)
                return out
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "ClientError")
                msg = e.response.get("Error", {}).get("Message", "") or str(e)
                err = ConnectorError(code, msg, retryable=code in RETRYABLE, hint=hint_for(code, msg))
            except ConnectorError as e:
                err = e
            except BotoCoreError as e:
                err = ConnectorError(type(e).__name__, str(e), retryable=False, hint=hint_for(type(e).__name__))
            audit("connector.error", {"session": inp.session_id, "code": err.code, "message": err.message, "hint": err.hint,
                                      "attempt": attempt}, run_id=self.run_id, target_id=self.target_id)
            if not err.retryable or attempt == self.max_retries:
                raise err
            log.warning("retryable %s, backing off %.1fs", err.code, delay)  # only when max_retries > 0
            time.sleep(delay)
            delay = min(delay * 2, 30)
        raise AssertionError("unreachable")
