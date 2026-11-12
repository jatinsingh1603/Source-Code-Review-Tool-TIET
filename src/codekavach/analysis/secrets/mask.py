"""Mask credential values in source text before it is shown (reports, dashboards).

``mask_secret_values`` replaces every detected secret with ``<SECRET:type>`` and keeps the number
of lines unchanged (a multi-line private key keeps its line count), so line numbers and locations
stay valid.
"""

from codekavach.analysis.secrets.stage import secret_registry
from codekavach.config.models.root import Settings
from codekavach.core.models import Language, RawCode
from codekavach.privacy.detect.runner import detect_all


def mask_secret_values(text: str, path: str, language: Language, settings: Settings) -> str:
    """``text`` with every detected secret replaced by its type tag; line count preserved."""
    try:
        spans = detect_all(
            RawCode(text),
            path=path,
            language=language,
            settings=settings,
            registry=secret_registry(),
        )
    except Exception:  # noqa: BLE001 - fail closed: show nothing rather than a value
        return "\n".join("<MASKED>" for _ in text.split("\n"))
    spans = tuple(s for s in spans if s.kind.value == "SECRET")
    if not spans:
        return text
    data = text.encode("utf-8", errors="surrogatepass")
    out: list[bytes] = []
    cursor = 0
    for span in spans:
        out.append(data[cursor : span.start_byte])
        newlines = data.count(b"\n", span.start_byte, span.end_byte)
        out.append(f"<SECRET:{span.subtype}>".encode() + b"\n" * newlines)
        cursor = span.end_byte
    out.append(data[cursor:])
    return b"".join(out).decode("utf-8", errors="replace")
