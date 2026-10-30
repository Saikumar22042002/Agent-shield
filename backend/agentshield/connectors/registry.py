"""Connector registry: one entry per target platform. Onboarding validation, the UI provider picker
and `build_connector` all read from here, so adding a platform is one entry + one connector class."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class ProviderSpec:
    key: str
    label: str
    implemented: bool
    identifier_label: str  # what the operator enters to identify the agent
    config_fields: list[str] = field(default_factory=list)  # required, stored in Target.config (non-AWS providers)
    optional_fields: list[str] = field(default_factory=list)  # accepted into Target.config when given
    note: str = ""
    kind: str = "cloud"  # cloud | local


PROVIDERS: dict[str, ProviderSpec] = {
    "aws_agentcore": ProviderSpec(
        key="aws_agentcore", label="AWS Bedrock AgentCore", implemented=True, identifier_label="Harness ARN",
        note="InvokeHarness via boto3 >= 1.43.99. Credentials from AWS profile, assumed role or instance role."),
    "azure_ai_foundry": ProviderSpec(
        key="azure_ai_foundry", label="Azure AI Foundry", implemented=False, identifier_label="Agent endpoint",
        config_fields=["endpoint", "agent_id"],
        note="Connector not implemented. Targets can be registered for inventory; connectivity checks are unsupported."),
    "gcp_agent": ProviderSpec(
        key="gcp_agent", label="Google Cloud agent", implemented=False, identifier_label="Agent resource name",
        config_fields=["resource_name", "location"],
        note="Connector not implemented. Targets can be registered for inventory; connectivity checks are unsupported."),
    "local_model": ProviderSpec(
        key="local_model", label="Local model (OpenAI-compatible)", implemented=True, identifier_label="",
        kind="local", config_fields=["base_url", "model"], optional_fields=["system_prompt", "temperature"],
        note="A model served on this machine (Ollama, LM Studio, llama.cpp, vLLM) through its OpenAI-compatible "
             "/chat/completions API. Loopback URLs only. Real model replies: results count as security evidence."),
    "local_stub": ProviderSpec(
        key="local_stub", label="Local stub (development)", implemented=True, identifier_label="",
        kind="local", optional_fields=["reply_delay_ms"],
        note="Built-in development target. No network, no model, no AWS. Replies are fixed text labelled as a stub; "
             "it tracks turns per session so conversation isolation can be checked. It never produces findings."),
}


class UnknownProvider(ValueError):
    pass


def get_provider(key: str) -> ProviderSpec:
    try:
        return PROVIDERS[key]
    except KeyError:
        raise UnknownProvider(f"Unknown provider '{key}'. Known: {', '.join(PROVIDERS)}") from None


def provider_list() -> list[dict]:
    return [asdict(p) for p in PROVIDERS.values()]


def connector_class(key: str):
    from .aws_agentcore import AgentCoreConnector
    from .local_model import LocalModelConnector
    from .local_stub import LocalStubConnector
    from .placeholders import AzureAIFoundryConnector, GCPAgentConnector

    return {"aws_agentcore": AgentCoreConnector, "azure_ai_foundry": AzureAIFoundryConnector,
            "gcp_agent": GCPAgentConnector, "local_model": LocalModelConnector,
            "local_stub": LocalStubConnector}[get_provider(key).key]
