"""Env-driven configuration. Every tunable lives here; nothing is hardcoded elsewhere."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ROOT / ".env", env_file_encoding="utf-8", extra="ignore")

    # --- server ---
    host: str = "127.0.0.1"
    port: int = 8000
    public_base_url: str = Field("http://127.0.0.1:8000", description="Base URL the trap callback links point at")
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    log_level: str = "INFO"
    # --- access control. Empty = local single-operator mode (operator name from X-Operator, loopback only).
    # Otherwise "name:token:role" entries, comma separated; role = viewer (read only) | operator | admin
    # (admin also resets the emergency stop). Tokens are compared in constant time and never logged.
    auth_tokens: str = Field("", repr=False)

    # --- storage ---
    database_url: str = f"sqlite:///{(ROOT / 'data' / 'agentshield.db').as_posix()}"
    reports_dir: Path = ROOT / "data" / "reports"

    # --- target (operator's own staging agent) ---
    target_name: str = "ServiceNow agent"
    target_harness_arn: str = ""
    target_qualifier: str = ""
    target_region: str = "us-east-1"
    target_environment: str = "staging"
    aws_profile: str = ""
    aws_role_arn: str = ""

    # --- models: LangChain init_chat_model ids ("<provider>:<model>"). No ids in code — set them in .env ---
    decision_model: str = ""  # all decision / judge work
    generation_model: str = ""
    google_api_key: str = Field("", repr=False)
    groq_api_key: str = Field("", repr=False)
    judge_batch_limit: int = 25

    # --- connectivity check (the only message AgentShield itself ever sends) ---
    connectivity_message: str = "Hello. This is a connectivity check from AgentShield. Please reply briefly with what you can help with."
    connectivity_min_interval_s: float = 10.0
    connector_timeout_s: int = 120

    # --- import scoring ---
    garak_fail_threshold: float = 0.5  # garak detector score >= threshold on an output = failed
    category_map_file: Path = ROOT / "backend" / "category_map.json"
    max_upload_mb: int = 200

    # --- assessment execution (all enforced in gateway.py, not the UI) ---
    technique_catalog_file: Path = ROOT / "backend" / "technique_catalog.json"
    max_prompts_per_technique: int = 5
    max_prompts_per_run: int = 50
    max_active_assessments: int = 1  # concurrent runs executing at once (others queue)
    technique_concurrency: int = 2  # test cases executed in parallel inside one run (isolated conversations)
    max_run_duration_s: int = 900
    invocation_timeout_s: int = 60
    min_invocation_interval_s: float = 0.25  # per-run rate limit between target prompts
    invocation_retries: int = 1  # retries on retryable connector errors (each retry is NOT a new prompt)
    attacker_token_budget: int = 60000  # Deep Agents / generation model tokens per run (when reported)
    target_token_budget: int = 0  # 0 = no limit; enforced only when the target reports usage
    # Providers the gateway may execute assessments against. Cloud providers are refused until explicitly
    # added on an authorised deployment, e.g. "local_stub,aws_agentcore" (connectivity checks are unaffected).
    assessment_providers: str = "local_stub,local_model"

    # --- engines ---
    # Orchestration always runs on a LangChain Deep Agents graph (coordinator + subagents). The coordinator's
    # chat model: "llm" = GENERATION_MODEL (needs its key), "deterministic" = AgentShield's scripted coordinator
    # model (no LLM; runs approved cases in plan order, skips a technique once its objective is established, stops
    # when the target is unavailable), "auto" = llm when GENERATION_MODEL is usable. The default sends nothing to a
    # model provider; "llm" / "auto" send the coordinator's state (case ids, labels, verdicts) to GENERATION_MODEL.
    coordinator_model: str = "deterministic"
    garak_python: Path = ROOT / "backend" / ".venv-garak" / "Scripts" / "python.exe"
    garak_timeout_s: int = 300
    gateway_public_url: str = ""  # where the garak subprocess reaches the gateway; default http://127.0.0.1:<PORT>
    evidence_dir: Path = ROOT / "data" / "evidence"  # raw framework outputs (garak report.jsonl, PyRIT export)
    # Benign prompt for the PyRIT plumbing test when the operator does not supply one in the plan.
    pyrit_benign_prompt: str = "Hello. Please reply with one short sentence describing what you can help with."

    def api_key_for(self, model: str) -> str:
        """API key for a "<provider>:<model>" id, by provider prefix. Empty if unknown/unset."""
        provider = model.split(":", 1)[0] if ":" in model else ""
        return {"google_genai": self.google_api_key, "groq": self.groq_api_key}.get(provider, "")

    @property
    def cors_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def garak_python_path(self) -> Path:
        """The isolated garak venv's interpreter (Scripts/python.exe on Windows, bin/python elsewhere)."""
        p = self.garak_python
        if not p.exists() and p.parent.name == "Scripts":
            alt = p.parent.parent / "bin" / "python"
            if alt.exists():
                return alt
        return p

    @property
    def auth_entries(self) -> dict[str, tuple[str, str]]:
        """token -> (name, role)."""
        out = {}
        for item in self.auth_tokens.split(","):
            parts = [x.strip() for x in item.split(":")]
            if len(parts) == 3 and all(parts) and parts[2] in ("viewer", "operator", "admin"):
                out[parts[1]] = (parts[0], parts[2])
        return out

    @property
    def assessment_provider_list(self) -> list[str]:
        return [p.strip() for p in self.assessment_providers.split(",") if p.strip()]

    def limits(self) -> dict:
        return {"max_prompts_per_technique": self.max_prompts_per_technique,
                "max_prompts_per_run": self.max_prompts_per_run,
                "max_run_duration_s": self.max_run_duration_s, "invocation_timeout_s": self.invocation_timeout_s,
                "min_invocation_interval_s": self.min_invocation_interval_s,
                "technique_concurrency": self.technique_concurrency, "invocation_retries": self.invocation_retries,
                "attacker_token_budget": self.attacker_token_budget, "target_token_budget": self.target_token_budget,
                "max_active_assessments": self.max_active_assessments}


@lru_cache
def get_settings() -> Settings:
    return Settings()
