"""Generate ``docs/reference/providers.md`` from the adapter registry (E22-04).

Owning epic: E22.

Run ``uv run python -m codekavach.llm.providers.docgen`` after changing an adapter, a capability, a
metadata row or a preset; ``tests/unit/llm/test_providers_doc.py`` fails while the committed file
differs from what this module renders, so a kind can never be missing from the page.
"""

import sys
from pathlib import Path
from typing import Final

from codekavach.config.models.llm import BUILTIN_PROVIDERS, PRESETS
from codekavach.llm.providers.registry import REGISTRY, load_provider_metadata

OUTPUT: Final = Path("docs") / "reference" / "providers.md"
_VERIFICATION: Final = {
    "live": "verified against a live endpoint",
    "offline": "verified offline (request building and recorded envelopes)",
    "unavailable": "no adapter in this build",
}


def _flag(value: bool) -> str:
    return "yes" if value else "no"


def render() -> str:
    """The Markdown page."""
    lines = [
        "# LLM providers",
        "",
        "<!-- Written by `uv run python -m codekavach.llm.providers.docgen`; do not edit. -->",
        "",
        "Every provider kind CodeKavach knows, the wire format its adapter speaks, and how far it "
        "has been verified. Adapters build requests and parse answers only; every request leaves "
        "through the egress guard, the ledger and the single transport (invariant I1).",
        "",
        "| kind | name | wire format | local | key | structured output | verification |",
        "|------|------|-------------|-------|-----|-------------------|--------------|",
    ]
    for kind, row in sorted(load_provider_metadata().items()):
        spec = REGISTRY.get(kind)
        modes = ", ".join(spec.capabilities.structured_modes) if spec is not None else "-"
        lines.append(
            f"| `{kind}` | {row.display_name} | {row.wire_format} | {_flag(row.local)} | "
            f"{_flag(row.needs_key)} | {modes} | {_VERIFICATION[row.verification]} |"
        )
    lines += [
        "",
        "## Retention notes",
        "",
    ]
    for kind, row in sorted(load_provider_metadata().items()):
        lines.append(f"- `{kind}`: {row.retention_note}")
    lines += [
        "",
        "## Presets",
        "",
        'A provider entry with `preset = "<name>"` takes the preset\'s endpoint, model, key '
        "reference and options; anything set explicitly in the entry wins.",
        "",
        "| preset | kind | endpoint | default model | key reference |",
        "|--------|------|----------|---------------|---------------|",
    ]
    for name, preset in sorted(PRESETS.items()):
        lines.append(
            f"| `{name}` | `{preset.kind.value}` | {preset.base_url or '-'} | "
            f"{preset.model or '-'} | {preset.api_key or 'kind default'} |"
        )
    lines += [
        "",
        "## Built-in providers",
        "",
        "These are present without configuration when named with `--provider <id>` (or as "
        "`llm.default_provider`) or when their key variable is set. `auto` never selects them.",
        "",
    ]
    for provider_id, variable in sorted(BUILTIN_PROVIDERS.items()):
        lines.append(f"- `{provider_id}`: key in `{variable}`")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    """Write the page (the test compares it; this module only writes)."""
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(render(), encoding="utf-8")
    sys.stdout.write(f"{OUTPUT}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
