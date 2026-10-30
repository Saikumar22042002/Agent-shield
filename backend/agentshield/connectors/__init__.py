from .base import Connector, ConnectorError, ConnectorInput, ConnectorOutput


class ConnectorUnsupported(Exception):
    """The target's provider has no implemented connector."""


def build_connector(target, *, timeout_s: int, run_id: str | None = None) -> Connector:
    """Factory keyed on target.provider (see registry.py)."""
    from ..safety import assert_staging
    from .registry import connector_class, get_provider

    assert_staging(target.environment)
    spec = get_provider(target.provider or "aws_agentcore")
    if not spec.implemented:
        raise ConnectorUnsupported(f"{spec.label}: connector not implemented — connectivity checks are unsupported.")
    cls = connector_class(spec.key)
    if spec.key in ("local_stub", "local_model"):
        return cls(run_id=run_id, target_id=target.id, config=dict(getattr(target, "config", None) or {}),
                   timeout_s=timeout_s)
    # Retries happen in the gateway (INVOCATION_RETRIES), where each one is a budgeted, audited Invocation;
    # the connector itself makes exactly one attempt.
    return cls(target.harness_arn, target.region, profile=target.aws_profile, role_arn=target.aws_role_arn,
               qualifier=target.qualifier, timeout_s=timeout_s, run_id=run_id, target_id=target.id, max_retries=0)


__all__ = ["Connector", "ConnectorError", "ConnectorInput", "ConnectorOutput", "ConnectorUnsupported",
           "build_connector"]
