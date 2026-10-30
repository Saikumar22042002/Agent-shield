import pytest

from agentshield.config import Settings
from agentshield.llm import ModelNotConfigured, decision_llm, generation_llm


def make(**kw) -> Settings:
    return Settings(_env_file=None, **kw)


def test_no_model_ids_in_code_defaults():
    st = make()
    assert st.decision_model == "" and st.generation_model == ""
    with pytest.raises(ModelNotConfigured, match="DECISION_MODEL is not set"):
        decision_llm(st)


def test_generation_model_from_env_value():
    st = make(generation_model="groq:qwen/qwen3.8-27b", groq_api_key="gsk_test")
    llm = generation_llm(st)
    assert type(llm).__name__ == "ChatGroq" and llm.model_name == "qwen/qwen3.8-27b"


def test_decision_model_uses_provider_key():
    st = make(decision_model="google_genai:some-model")
    with pytest.raises(ModelNotConfigured, match="GOOGLE_API_KEY is empty"):
        decision_llm(st)
    st = make(decision_model="groq:qwen/qwen3.8-27b", groq_api_key="gsk_test")
    assert type(decision_llm(st)).__name__ == "ChatGroq"


def test_unsupported_provider_rejected():
    with pytest.raises(ModelNotConfigured, match="provider must be one of"):
        decision_llm(make(decision_model="anthropic:anything"))


def test_api_key_not_in_repr():
    assert "gsk_secret" not in repr(make(groq_api_key="gsk_secret"))
