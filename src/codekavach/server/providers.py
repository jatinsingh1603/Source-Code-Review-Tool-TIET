"""LLM providers as the server sees them: configured providers, adapters and a probe.

Owning epic: E32.

The list comes from the configuration (``llm.providers``, including presets added by E22) and the
adapter registry, discovered at run time so new adapters appear without a change here. Keys are
shown only as references and their availability (``configured``), never as values. ``test``
calls the provider probe of ``codekavach.llm.providers``; the probe, not the server, decides
whether a request leaves the machine, and it does so through the egress transport (I1).
"""

import inspect
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from codekavach.core.log import get_logger

if TYPE_CHECKING:
    from codekavach.config import Settings

_log = get_logger("codekavach.server.providers")

NAMES: Final = {
    "mock": "Mock (offline)",
    "replay": "Replay (recorded answers)",
    "agentrouter": "AgentRouter (OpenAI Responses)",
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "gemini": "Google Gemini",
    "ollama": "Ollama (local)",
}


WIRE: Final = {
    "anthropic": "Anthropic Messages API",
    "openai": "OpenAI Chat Completions",
    "azure-openai": "Azure OpenAI Chat Completions",
    "openai-compatible": "OpenAI-compatible Chat Completions",
    "litellm": "OpenAI-compatible Chat Completions (LiteLLM)",
    "gemini": "Google Gemini generateContent",
    "vertex": "Vertex AI generateContent",
    "xai": "xAI Chat Completions",
    "bedrock": "Amazon Bedrock Converse",
    "ollama": "Ollama /api/chat",
    "mock": "in process (no network)",
    "replay": "recorded answers (no network)",
    "cli-bridge": "local CLI bridge",
}


def key_state(ref: str) -> str:
    """``set``, ``not-set``, ``backend-unavailable`` or ``error`` (never the value)."""
    try:
        from codekavach.config import keys  # noqa: PLC0415

        return str(keys.secret_status(ref, project_root=None).state)
    except Exception:  # noqa: BLE001 - an unknown state is reported as an error
        return "error"


def _secret_state(ref: str, settings: "Settings") -> bool:
    return key_state(ref) == "set"


def wire_format(kind: str, options: Any) -> str:
    """The request protocol an adapter of ``kind`` speaks (``wire_api`` option first)."""
    wire_api = options.get("wire_api") if isinstance(options, dict) else None
    if wire_api == "responses":
        return "OpenAI Responses API"
    if wire_api == "chat":
        return "OpenAI-compatible Chat Completions"
    return WIRE.get(kind, kind)


def _adapters(settings: "Settings") -> dict[str, Any]:
    try:
        from codekavach.core.plugins.registry import registry_from_environment  # noqa: PLC0415

        return dict(registry_from_environment(settings).providers())
    except Exception as error:  # noqa: BLE001 - no registry means no adapters, not a crash
        _log.info("server_provider_registry_unavailable", error_type=type(error).__name__)
        return {}


def _capabilities(adapter: Any) -> dict[str, Any]:
    source = getattr(adapter, "capabilities", None)
    result: dict[str, Any] = {}
    for name in ("structured_output", "tool_calling", "context_window", "batch", "local"):
        value = getattr(source, name, None)
        result[name] = value if name == "context_window" else bool(value)
    return result


def list_providers(settings: "Settings", default: str | None) -> list[dict[str, Any]]:
    """One row per configured provider."""
    from codekavach.config import keys  # noqa: PLC0415

    adapters = _adapters(settings)
    rows = []
    for provider_id, provider in settings.llm.providers.items():
        kind = str(getattr(provider.kind, "value", provider.kind))
        refs = list(keys.effective_key_refs(kind, provider.api_key))
        states: list[dict[str, Any]] = []
        for ref in refs:
            found = key_state(ref)
            states.append({"ref": ref, "state": found, "present": found == "set"})
        configured = not refs or any(item["present"] for item in states)
        model = provider.model or settings.llm.model
        options = dict(getattr(provider, "options", {}) or {})
        models = [model] if model else []
        for extra in options.get("models", []):
            if isinstance(extra, str) and extra not in models:
                models.append(extra)
        adapter = adapters.get(kind)
        rows.append(
            {
                "id": provider_id,
                "name": NAMES.get(provider_id, provider_id),
                "kind": kind,
                "models": models,
                "default_model": model,
                "local": not provider.is_remote,
                "configured": configured,
                "enabled": provider.enabled,
                "host": provider.host,
                "key_refs": refs,
                "key_ref_status": states,
                "wire": wire_format(kind, options),
                "endpoint": str(provider.base_url) if provider.base_url else None,
                "preset": provider.preset,
                "adapter": adapter is not None or kind in {"mock", "replay"},
                "default": provider_id == default,
                "trust_tier": str(provider.effective_trust_tier.value),
                "min_level": str(settings.privacy.floor_for_tier(
                    provider.effective_trust_tier).value),
                "capabilities": _capabilities(adapter),
            }
        )  # fmt: skip
    return rows


def test_provider(
    provider_id: str, settings: "Settings", model: str | None, state_dir: Path | None = None
) -> dict[str, Any]:
    """Probe ``provider_id``: ``{ok, latency_ms, model, message}``."""
    provider = settings.llm.providers.get(provider_id)
    if provider is None:
        return {"ok": False, "latency_ms": 0, "model": model, "message": "provider_not_configured"}
    chosen = model or provider.model or settings.llm.model
    try:
        from codekavach.llm import providers as llm_providers  # noqa: PLC0415
        from codekavach.llm.providers import base  # noqa: PLC0415

        probe = getattr(llm_providers, "probe_provider", None) or base.probe_provider
    except ImportError:
        return {"ok": False, "latency_ms": 0, "model": chosen, "message": "backend_unavailable"}
    offered: dict[str, Any] = {"model": chosen, "timeout": 60.0, "structured": False}
    if state_dir is not None:
        state_dir.mkdir(parents=True, exist_ok=True)
        offered["state_dir"] = state_dir
    try:
        from codekavach.core.pipeline.context import ConsentDecision  # noqa: PLC0415

        offered["consent"] = ConsentDecision(granted=True, source="flag")
    except ImportError:
        pass
    parameters = inspect.signature(probe).parameters
    open_ended = any(item.kind is item.VAR_KEYWORD for item in parameters.values())
    kwargs = {name: value for name, value in offered.items() if open_ended or name in parameters}
    started = time.perf_counter()
    try:
        result = probe(provider_id, settings, **kwargs)
    except Exception as error:  # noqa: BLE001 - a failed probe is a result, not a crash
        return {
            "ok": False,
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "model": chosen,
            "message": f"probe_failed: {type(error).__name__}",
        }
    latency = getattr(result, "latency_ms", None)
    if not isinstance(latency, int | float):
        latency = (time.perf_counter() - started) * 1000
    message = (
        getattr(result, "message", None)
        or getattr(result, "reason_code", None)
        or getattr(result, "reason", None)
        or ("ok" if getattr(result, "ok", False) else "failed")
    )
    network = getattr(result, "network", None)
    extra = {
        name: getattr(result, name)
        for name in ("prompt_tokens", "completion_tokens", "structured_output", "ledger_seq")
        if getattr(result, name, None) is not None
    }
    return {
        **extra,
        "ok": getattr(result, "ok", False) is True,
        "latency_ms": int(latency),
        "model": getattr(result, "model", None) or chosen,
        "message": str(message),
        "network": network,
    }
