"""LLM providers: the base protocol and adapters.

Owning epic: E22. Normative layout: docs/ARCHITECTURE.md section 3.

``probe_provider`` is the entry point ``codekavach providers test`` reaches by name; it is
imported lazily so that importing an adapter does not load the egress session.
"""

from typing import Any


def probe_provider(provider_id: str, settings: Any, **options: Any) -> Any:
    """Send the constant probe to ``provider_id``; see ``codekavach.llm.providers.probe``."""
    from codekavach.llm.providers.probe import probe_provider as probe  # noqa: PLC0415

    return probe(provider_id, settings, **options)


__all__ = ["probe_provider"]
