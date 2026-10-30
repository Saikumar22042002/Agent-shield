"""Chat-model factory for DECISION_MODEL and GENERATION_MODEL ("<provider>:<model>" ids from .env).

APIs (verified against installed packages 2026-10-29):
  langchain.chat_models.init_chat_model("<provider>:<model>", api_key=...)  langchain 1.4.x
    provider "groq"         -> langchain_groq.ChatGroq(model=, api_key=)                     langchain-groq 1.1.3
    provider "google_genai" -> langchain_google_genai.ChatGoogleGenerativeAI(model=, api_key=) langchain-google-genai 4.4.2
"""
from __future__ import annotations

from .config import Settings, get_settings

SUPPORTED_PROVIDERS = ("google_genai", "groq")


class ModelNotConfigured(RuntimeError):
    pass


def _chat_model(setting: str, model: str, st: Settings):
    if not model:
        raise ModelNotConfigured(f"{setting} is not set in .env (format: <provider>:<model>).")
    provider = model.split(":", 1)[0] if ":" in model else ""
    if provider not in SUPPORTED_PROVIDERS:
        raise ModelNotConfigured(f"{setting}={model!r}: provider must be one of {', '.join(SUPPORTED_PROVIDERS)}.")
    key = st.api_key_for(model)
    if not key:
        env = "GOOGLE_API_KEY" if provider == "google_genai" else "GROQ_API_KEY"
        raise ModelNotConfigured(f"{setting} uses {provider} but {env} is empty.")
    from langchain.chat_models import init_chat_model

    return init_chat_model(model, api_key=key, temperature=0)


def decision_llm(settings: Settings | None = None):
    st = settings or get_settings()
    return _chat_model("DECISION_MODEL", st.decision_model, st)


def generation_llm(settings: Settings | None = None):
    st = settings or get_settings()
    return _chat_model("GENERATION_MODEL", st.generation_model, st)
