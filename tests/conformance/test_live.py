"""Live conformance: the probe against a real provider (E22-04).

Skipped, never failed, unless ``CODEKAVACH_CONFORMANCE_LIVE=1`` is set and the provider's key
reference resolves. Never run in CI. The provider ids are taken from
``CODEKAVACH_CONFORMANCE_PROVIDERS`` (comma separated, default ``agentrouter``).
"""

import os
from pathlib import Path

import pytest

from codekavach.config import Settings
from codekavach.config.models.llm import key_available
from codekavach.core.pipeline.context import ConsentDecision
from codekavach.llm.providers.probe import probe_provider
from codekavach.llm.selection import ProviderNotConfigured, settings_for_provider
from tests.conformance.support import LIVE_VARIABLE

pytestmark = [pytest.mark.conformance, pytest.mark.enable_socket]

PROVIDERS = [
    name.strip()
    for name in os.environ.get("CODEKAVACH_CONFORMANCE_PROVIDERS", "agentrouter").split(",")
    if name.strip()
]


@pytest.mark.parametrize("provider_id", PROVIDERS)
def test_the_provider_answers_the_probe_with_a_valid_verdict(
    provider_id: str, tmp_path: Path
) -> None:
    if os.environ.get(LIVE_VARIABLE) != "1" or os.environ.get("CI"):
        pytest.skip(f"live conformance runs only with {LIVE_VARIABLE}=1 and never in CI")
    try:
        settings = settings_for_provider(Settings(), provider_id)
    except ProviderNotConfigured:
        pytest.skip(f"provider {provider_id} is not configured")
    if not key_available(settings.llm.providers[provider_id]):
        pytest.skip(f"the key reference of {provider_id} does not resolve")
    outcome = probe_provider(
        provider_id,
        settings,
        structured=True,
        timeout=90.0,
        consent=ConsentDecision(granted=True, source="flag"),
        state_dir=tmp_path,
    )
    assert outcome.ok, outcome.reason_code
    assert outcome.structured_output == "passed"
