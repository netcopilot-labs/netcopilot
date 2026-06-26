"""LLM provider abstraction — driven by the model registry (``models.yaml``).

``get_provider(model_id)`` looks the id up in the registry and builds the right
provider (native Claude for ``type: anthropic``, the OpenAI-compatible client for
``type: openai`` — vLLM/Ollama/OpenAI/Gemini/…). With no models.yaml the registry
falls back to the legacy Claude + local pair from env vars, so old installs and the
bare ``"claude"`` / ``"local"`` ids keep working. The orchestrator depends only on
``LLMProvider`` / ``LLMResult``.
"""

from __future__ import annotations

import os

from .base import LLMProvider, LLMResult, ToolCall
from .registry import ModelConfig, load_registry

__all__ = ["LLMProvider", "LLMResult", "ToolCall", "get_provider", "build_provider"]


def build_provider(cfg: ModelConfig) -> LLMProvider:
    """Instantiate the provider for a model config."""
    api_key = os.environ.get(cfg.api_key_env) if cfg.api_key_env else None
    if cfg.type == "anthropic":
        from .claude import ClaudeProvider

        return ClaudeProvider(api_key=api_key, model=cfg.model)
    from .ollama import OllamaProvider

    return OllamaProvider(base_url=cfg.base_url, model=cfg.model, api_key=api_key)


def get_provider(model_id: str | None = None) -> LLMProvider:
    """Return the provider for a registry model id (or the registry default)."""
    models, default_id = load_registry()
    model_id = model_id or default_id
    cfg = next((m for m in models if m.id == model_id), None)
    if cfg is None:
        # Back-compat for the bare provider names used before the registry.
        legacy = (model_id or "").lower()
        if legacy == "claude":
            cfg = ModelConfig(
                id="claude", label="claude", type="anthropic",
                model=os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6"),
                api_key_env="ANTHROPIC_API_KEY", anonymize=True,
            )
        elif legacy in ("local", "ollama"):
            cfg = ModelConfig(
                id="local", label="local", type="openai",
                model=os.environ.get("OLLAMA_MODEL", "llama3.1"),
                base_url=os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
                anonymize=False,
            )
        else:
            raise ValueError(f"Unknown model id: {model_id!r}")
    return build_provider(cfg)
