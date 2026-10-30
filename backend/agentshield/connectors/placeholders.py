"""Placeholder connectors for platforms on the roadmap but not implemented.

They let the registry, onboarding UI and data model be multi-cloud today. `send` raises
ConnectorError("NotImplemented", ...): no network call is made and no API shape is assumed.
To implement one, read the provider's current API reference and mirror aws_agentcore.AgentCoreConnector
(assemble the full reply, capture usage + latency, map errors to operator messages, audit request and
response), then set implemented=True for it in registry.py.
"""
from __future__ import annotations

import uuid

from .base import ConnectorError, ConnectorInput, ConnectorOutput


class _NotImplementedConnector:
    label = ""

    def __init__(self, target, **_kw):
        self.target = target

    def new_session_id(self) -> str:
        return f"agentshield-{uuid.uuid4()}"

    def send(self, inp: ConnectorInput) -> ConnectorOutput:
        raise ConnectorError("NotImplemented", f"The {self.label} connector is not implemented yet.")


class AzureAIFoundryConnector(_NotImplementedConnector):
    label = "Azure AI Foundry"


class GCPAgentConnector(_NotImplementedConnector):
    label = "Google Cloud agent"
