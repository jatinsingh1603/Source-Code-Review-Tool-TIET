"""Record a provider conformance cassette from a real endpoint (E22-04).

Usage::

    CODEKAVACH_AGENTROUTER_API_KEY_FILE=/path/to/key \\
        uv run python tools/record_conformance.py agentrouter --name openai-responses

The request is the bundled synthetic probe payload (``codekavach.privacy.egress.probe``) rendered
by the triage task and prepared by the provider's adapter. It goes through the egress guard, the
ledger and the transport exactly like ``codekavach providers test`` (I1). The tool refuses a
payload whose hash is not listed in ``tests/conformance/allowed_payloads.txt``, so a cassette can
never hold client code.

The cassette (``tests/conformance/cassettes/<name>/<payload_hash>.json``) is in the replay
provider's format and holds the response body only: no request or response header (so no
authorisation header) and no account identifier; response ids and account fields are replaced
by ``"redacted"``. It records the provider kind, the model and the date of the run, because
hosted model snapshots are retired on a published schedule.

Refused when ``CI`` is set: a pipeline never records.
"""

import argparse
import datetime
import json
import os
import sys
from pathlib import Path
from typing import Any, Final

ROOT: Final = Path(__file__).resolve().parents[1]
CONFORMANCE: Final = ROOT / "tests" / "conformance"
ALLOW_LIST: Final = CONFORMANCE / "allowed_payloads.txt"
CASSETTES: Final = CONFORMANCE / "cassettes"
REDACTED: Final = "redacted"
# Response fields that identify an account, an organisation or a single request.
ACCOUNT_FIELDS: Final = frozenset(
    {
        "id",
        "user",
        "organization",
        "organization_id",
        "project",
        "project_id",
        "safety_identifier",
        "prompt_cache_key",
        "previous_response_id",
        "system_fingerprint",
        "responseId",
        "metadata",
        # Opaque vendor blobs and the echo of our own instructions: not needed to parse.
        "encrypted_content",
        "instructions",
    }
)
FORBIDDEN_TEXT: Final = ("authorization", "bearer ", "x-api-key", "api-key", "x-goog-api-key")


class RecordError(Exception):
    """The cassette must not be recorded."""


def allowed_hashes(path: Path = ALLOW_LIST) -> frozenset[str]:
    """The payload hashes that may be recorded."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return frozenset(line.strip() for line in lines if line.strip() and not line.startswith("#"))


def check_allowed(payload_hash: str, allowed: frozenset[str]) -> None:
    """Refuse a payload that is not on the allow-list.

    Raises:
        RecordError: the hash is not listed.
    """
    if payload_hash not in allowed:
        raise RecordError(
            f"payload {payload_hash[:12]} is not in {ALLOW_LIST.name}; only the bundled "
            "synthetic payload may be recorded"
        )


def scrub(value: Any) -> Any:
    """``value`` with every account or request identifier replaced by ``"redacted"``."""
    if isinstance(value, dict):
        return {
            key: (REDACTED if key in ACCOUNT_FIELDS and item is not None else scrub(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [scrub(item) for item in value]
    return value


def cassette_document(
    *,
    payload_hash: str,
    status: int,
    body: bytes,
    kind: str,
    wire_format: str,
    model: str,
    host: str | None,
    prompt_version: str,
    recorded_at: str,
) -> dict[str, Any]:
    """The cassette for one recorded response; holds no header.

    Raises:
        RecordError: the body is not JSON, or still names an authorisation header.
    """
    try:
        document = json.loads(body)
    except ValueError:
        raise RecordError("the response body is not JSON; nothing was recorded") from None
    cassette = {
        "payload_hash": payload_hash,
        "status": status,
        "body": scrub(document),
        "conformance": {
            "kind": kind,
            "wire_format": wire_format,
            "model": model,
            "host": host,
            "prompt_version": prompt_version,
            "recorded_at": recorded_at,
            "payload": "codekavach.privacy.egress.probe.PROBE_SNIPPET",
        },
    }
    text = json.dumps(cassette).lower()
    for forbidden in FORBIDDEN_TEXT:
        if forbidden in text:
            raise RecordError(f"the response names {forbidden!r}; nothing was recorded")
    return cassette


def record(provider_id: str, name: str, *, model: str | None, timeout: float) -> Path:
    """Send the probe payload to ``provider_id`` and write its cassette.

    Raises:
        RecordError: recording is not allowed, or the provider did not answer usefully.
    """
    if os.environ.get("CI"):
        raise RecordError("recording is refused when CI is set")
    from codekavach.config import Settings  # noqa: PLC0415 - after the CI check
    from codekavach.core.pipeline.context import ConsentDecision  # noqa: PLC0415
    from codekavach.llm.providers.probe import exchange_probe  # noqa: PLC0415
    from codekavach.llm.providers.registry import load_provider_metadata  # noqa: PLC0415
    from codekavach.llm.selection import settings_for_provider  # noqa: PLC0415
    from codekavach.privacy.egress.probe import probe_payload  # noqa: PLC0415

    check_allowed(probe_payload().payload_hash, allowed_hashes())
    settings = settings_for_provider(Settings(), provider_id, model=model)
    configured = settings.llm.providers[provider_id]
    consent = ConsentDecision(granted=True, source="flag")
    sent = exchange_probe(provider_id, settings, model=model, timeout=timeout, consent=consent)
    check_allowed(sent.request.payload_hash, allowed_hashes())
    result = sent.result
    if result.kind != "answered" or not 200 <= (result.status or 0) < 300:
        raise RecordError(f"the provider did not answer: {result.kind} status={result.status}")
    kind = configured.kind.value
    cassette = cassette_document(
        payload_hash=sent.request.payload_hash,
        status=result.status or 200,
        body=result.body,
        kind=kind,
        wire_format=load_provider_metadata()[kind].wire_format,
        model=sent.request.model,
        host=configured.host,
        prompt_version=sent.request.prompt_version,
        recorded_at=datetime.datetime.now(datetime.UTC).date().isoformat(),
    )
    target = CASSETTES / name / f"{sent.request.payload_hash}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(cassette, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("provider", help="provider id, for example agentrouter")
    parser.add_argument("--name", required=True, help="cassette directory name (the wire format)")
    parser.add_argument("--model", default=None, help="model to record (default: the preset's)")
    parser.add_argument("--timeout", type=float, default=60.0, help="seconds allowed")
    args = parser.parse_args(argv)
    try:
        path = record(args.provider, args.name, model=args.model, timeout=args.timeout)
    except RecordError as error:
        print(f"refused: {error}", file=sys.stderr)
        return 2
    print(f"recorded {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
