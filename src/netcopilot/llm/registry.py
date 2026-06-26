"""Model registry — user-configurable list of LLMs from a ``models.yaml`` file.

A model entry declares everything needed to reach a model and display it:

    id          stable identifier (used by the API + selection)
    label       human label shown in the UI
    type        "anthropic" (native Claude) | "openai" (any OpenAI-compatible
                endpoint: vLLM, Ollama, OpenAI/ChatGPT, Gemini's OpenAI endpoint, …)
    model       the provider-side model name
    base_url    OpenAI-compatible endpoint (openai type only); ${VARS} expanded
    api_key_env name of the .env var holding the API key (never the key itself)
    anonymize   scrub identifiers before sending (default True; set False for local)
    price_in    USD per 1M input tokens  (for the cost panel; 0 = free/unknown)
    price_out   USD per 1M output tokens

Secrets never live in this file — only the *name* of the env var that holds them.
If no ``models.yaml`` exists, the registry falls back to the legacy two-model setup
derived from environment variables, so existing installs keep working unchanged.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ModelConfig:
    id: str
    label: str
    type: str  # "anthropic" | "openai"
    model: str
    base_url: str | None = None
    api_key_env: str | None = None
    anonymize: bool = True
    price_in: float = 0.0
    price_out: float = 0.0


def _registry_path() -> Path | None:
    """Locate models.yaml: $MODELS_CONFIG, then CWD, then repo root."""
    env = os.environ.get("MODELS_CONFIG")
    if env:
        p = Path(env)
        return p if p.exists() else None
    here = Path(__file__).resolve()
    for cand in (Path.cwd() / "models.yaml", here.parents[3] / "models.yaml"):
        if cand.exists():
            return cand
    return None


def _expand(v):
    return os.path.expandvars(v) if isinstance(v, str) else v


def _legacy_models() -> list[ModelConfig]:
    """Back-compat: the original Claude + local pair, from env vars."""
    claude_model = os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6")
    local_model = os.environ.get("OLLAMA_MODEL", "local model")
    return [
        ModelConfig(
            id="claude", label=f"{claude_model} (anonymized)", type="anthropic",
            model=claude_model, api_key_env="ANTHROPIC_API_KEY",
            anonymize=True, price_in=3.0, price_out=15.0,
        ),
        ModelConfig(
            id="local", label=f"{local_model} (Local)", type="openai",
            model=local_model,
            base_url=os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
            anonymize=False,
        ),
    ]


def load_registry() -> tuple[list[ModelConfig], str]:
    """Return (models, default_id). Falls back to the legacy pair if no models.yaml."""
    path = _registry_path()
    models: list[ModelConfig] = []
    default_id: str | None = None
    if path is not None:
        import yaml

        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        default_id = data.get("default")
        for m in data.get("models", []):
            mtype = m.get("type", "openai")
            models.append(
                ModelConfig(
                    id=m["id"],
                    label=m.get("label", m["id"]),
                    type=mtype,
                    model=m["model"],
                    base_url=_expand(m.get("base_url")),
                    api_key_env=m.get("api_key_env"),
                    anonymize=bool(m.get("anonymize", True)),
                    price_in=float(m.get("price_in", 0) or 0),
                    price_out=float(m.get("price_out", 0) or 0),
                )
            )
    if not models:
        models = _legacy_models()
        default_id = None

    valid = {m.id for m in models}
    # Precedence for the default: NETCOPILOT_LLM env > models.yaml `default:` > first.
    env_default = os.environ.get("NETCOPILOT_LLM")
    if env_default in valid:
        default_id = env_default
    if default_id not in valid:
        default_id = models[0].id
    return models, default_id


def load_models() -> list[ModelConfig]:
    return load_registry()[0]


def get_model(model_id: str) -> ModelConfig | None:
    return next((m for m in load_models() if m.id == model_id), None)


def is_configured(cfg: ModelConfig) -> bool:
    """True when the model has what it needs to actually run.

    A model that references an API key needs that env var set; a keyless local
    endpoint needs a resolved base_url (an unexpanded ``${VAR}`` means the var is
    missing). Used to hide not-yet-configured models from the selector.
    """
    if cfg.api_key_env:
        return bool(os.environ.get(cfg.api_key_env))
    if cfg.type == "openai":
        return bool(cfg.base_url) and "${" not in cfg.base_url
    return True
