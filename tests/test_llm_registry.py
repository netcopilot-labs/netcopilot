"""Model registry: models.yaml loading, legacy fallback, provider construction."""

from netcopilot.llm import get_provider
from netcopilot.llm.claude import ClaudeProvider
from netcopilot.llm.ollama import OllamaProvider
from netcopilot.llm.registry import get_model, is_configured, load_registry

_YAML = """
default: gpt
models:
  - id: local-x
    label: Local X
    type: openai
    base_url: http://host:8000/v1
    model: x-7b
    anonymize: false
  - id: gpt
    label: GPT-4o
    type: openai
    base_url: https://api.openai.com/v1
    model: gpt-4o
    api_key_env: OPENAI_API_KEY
    anonymize: true
    price_in: 2.5
    price_out: 10
  - id: claude-s
    label: Claude
    type: anthropic
    model: claude-sonnet-4-6
    api_key_env: ANTHROPIC_API_KEY
    anonymize: true
"""


def _use_yaml(monkeypatch, tmp_path, text=_YAML):
    y = tmp_path / "models.yaml"
    y.write_text(text)
    monkeypatch.setenv("MODELS_CONFIG", str(y))
    monkeypatch.delenv("NETCOPILOT_LLM", raising=False)
    return y


def test_registry_loads_models_yaml(monkeypatch, tmp_path):
    _use_yaml(monkeypatch, tmp_path)
    models, default_id = load_registry()
    assert [m.id for m in models] == ["local-x", "gpt", "claude-s"]
    assert default_id == "gpt"  # from `default:`
    assert get_model("local-x").anonymize is False
    assert get_model("gpt").anonymize is True
    assert get_model("gpt").price_in == 2.5 and get_model("gpt").price_out == 10


def test_env_default_overrides_yaml_default(monkeypatch, tmp_path):
    _use_yaml(monkeypatch, tmp_path)
    monkeypatch.setenv("NETCOPILOT_LLM", "local-x")
    assert load_registry()[1] == "local-x"


def test_legacy_fallback_without_yaml(monkeypatch, tmp_path):
    # MODELS_CONFIG pointing at a missing file -> legacy claude+local pair.
    monkeypatch.setenv("MODELS_CONFIG", str(tmp_path / "absent.yaml"))
    ids = {m.id for m in load_registry()[0]}
    assert ids == {"claude", "local"}


def test_get_provider_openai_compatible(monkeypatch, tmp_path):
    _use_yaml(monkeypatch, tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    p = get_provider("gpt")
    assert isinstance(p, OllamaProvider)
    assert p.base_url == "https://api.openai.com/v1"
    assert p.model == "gpt-4o"
    assert p.api_key == "sk-test"


def test_get_provider_local_has_no_key(monkeypatch, tmp_path):
    _use_yaml(monkeypatch, tmp_path)
    p = get_provider("local-x")
    assert isinstance(p, OllamaProvider) and p.api_key is None
    assert p.base_url == "http://host:8000/v1"


def test_get_provider_anthropic(monkeypatch, tmp_path):
    _use_yaml(monkeypatch, tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    p = get_provider("claude-s")
    assert isinstance(p, ClaudeProvider)
    assert p.model == "claude-sonnet-4-6"


def test_is_configured(monkeypatch, tmp_path):
    _use_yaml(monkeypatch, tmp_path)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    assert is_configured(get_model("local-x")) is True   # local: base_url present
    assert is_configured(get_model("gpt")) is False       # needs OPENAI_API_KEY (unset)
    assert is_configured(get_model("claude-s")) is True   # ANTHROPIC_API_KEY set


def test_is_configured_unexpanded_base_url(monkeypatch, tmp_path):
    monkeypatch.delenv("MISSING_URL", raising=False)
    text = (
        "models:\n"
        "  - id: g\n    label: G\n    type: openai\n"
        "    base_url: ${MISSING_URL}\n    model: m\n    anonymize: false\n"
    )
    _use_yaml(monkeypatch, tmp_path, text)
    assert is_configured(get_model("g")) is False  # ${MISSING_URL} never expanded


def test_base_url_env_expansion(monkeypatch, tmp_path):
    monkeypatch.setenv("MY_VLLM", "http://10.0.0.9:8000/v1")
    text = (
        "models:\n"
        "  - id: g\n    label: G\n    type: openai\n"
        "    base_url: ${MY_VLLM}\n    model: gemma\n    anonymize: false\n"
    )
    _use_yaml(monkeypatch, tmp_path, text)
    assert get_model("g").base_url == "http://10.0.0.9:8000/v1"
