"""Deterministic, accessible charts as inline SVG strings, generated in Python.

Owning epic: E31 (E31-01).

The PDF path runs no JavaScript, so charts are static SVG with a ``<title>`` per mark (the HTML
report shows it as a tooltip), a text label on every bar (identity is never colour alone), thin
rounded bars on a recessive axis, and no external reference of any kind. The same input always
gives byte-identical output. Every text value is XML-escaped.
"""

from collections.abc import Sequence
from xml.sax.saxutils import escape

from codekavach.report.render.theme import DEFAULT_THEME, Theme

_FONT = 'font-family="Helvetica, Arial, sans-serif"'


def _e(text: object) -> str:
    return escape(str(text), {'"': "&quot;"})


def bar_chart(
    rows: Sequence[tuple[str, int, str]],
    *,
    title: str,
    width: int = 520,
    label_width: int = 190,
    theme: Theme = DEFAULT_THEME,
) -> str:
    """A horizontal bar chart: one row per ``(label, value, colour)``."""
    bar_h, gap, top = 18, 10, 8
    height = top + len(rows) * (bar_h + gap) + 4
    if not rows:
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" role="img" width="{width}" height="40" '
            f'viewBox="0 0 {width} 40"><title>{_e(title)}</title><text x="0" y="24" {_FONT} '
            f'font-size="12" class="mut" fill="{theme.muted}">No data</text></svg>'
        )
    peak = max(value for _, value, _ in rows) or 1
    plot = width - label_width - 40
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="{_e(title)}" '
        f'width="{width}" height="{height}" viewBox="0 0 {width} {height}" class="ck-chart">',
        f"<title>{_e(title)}</title>",
        f'<line x1="{label_width}" y1="{top - 4}" x2="{label_width}" y2="{height - 2}" '
        f'stroke="{theme.rule}" stroke-width="1"/>',
    ]
    for index, (label, value, colour) in enumerate(rows):
        y = top + index * (bar_h + gap)
        length = max(int(plot * value / peak), 3 if value else 0)
        shown = label if len(label) <= 30 else label[:29] + "…"
        parts.append(
            f'<text x="{label_width - 8}" y="{y + bar_h - 5}" text-anchor="end" {_FONT} '
            f'font-size="11" class="ink" fill="{theme.ink}">{_e(shown)}</text>'
        )
        if length:
            parts.append(
                f'<rect x="{label_width + 1}" y="{y}" width="{length}" height="{bar_h}" rx="4" '
                f'fill="{colour}"><title>{_e(label)}: {value}</title></rect>'
            )
        parts.append(
            f'<text x="{label_width + length + 6}" y="{y + bar_h - 5}" {_FONT} font-size="11" '
            f'font-weight="600" class="ink" fill="{theme.ink}">{value}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def severity_chart(counts: Sequence[tuple[str, int]], *, theme: Theme = DEFAULT_THEME) -> str:
    """Findings by severity."""
    rows = [(name.title(), count, theme.severity(name)) for name, count in counts]
    return bar_chart(rows, title="Findings by severity", label_width=90, theme=theme)


def donut(
    counts: Sequence[tuple[str, int]], *, theme: Theme = DEFAULT_THEME, size: int = 150
) -> str:
    """A severity donut with the total in the centre and a 2px surface gap between segments."""
    import math  # noqa: PLC0415

    total = sum(count for _, count in counts)
    radius, stroke = size / 2 - 12, 22
    cx = cy = size / 2
    circumference = 2 * math.pi * radius
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Severity distribution" '
        f'width="{size}" height="{size}" viewBox="0 0 {size} {size}" class="ck-chart">',
        "<title>Severity distribution</title>",
        f'<circle cx="{cx}" cy="{cy}" r="{radius:.2f}" fill="none" stroke="{theme.rule}" '
        f'stroke-width="{stroke}"/>',
    ]
    offset = 0.0
    for name, count in counts:
        if not count or not total:
            continue
        length = circumference * count / total
        visible = max(length - 2, 0.5) if len([c for _, c in counts if c]) > 1 else length
        parts.append(
            f'<circle cx="{cx}" cy="{cy}" r="{radius:.2f}" fill="none" '
            f'stroke="{theme.severity(name)}" stroke-width="{stroke}" '
            f'stroke-dasharray="{visible:.2f} {circumference - visible:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {cx} {cy})">'
            f"<title>{_e(name.title())}: {count}</title></circle>"
        )
        offset += length
    parts.append(
        f'<text x="{cx}" y="{cy + 2}" text-anchor="middle" {_FONT} font-size="28" '
        f'font-weight="700" class="ink" fill="{theme.ink}">{total}</text>'
        f'<text x="{cx}" y="{cy + 20}" text-anchor="middle" {_FONT} font-size="10" '
        f'class="mut" fill="{theme.muted}">FINDINGS</text></svg>'
    )
    return "".join(parts)


_BAND_FILL = {
    "critical": "#e9d5f5",
    "high": "#fbd5d5",
    "medium": "#fde3c8",
    "low": "#fbf0c4",
    "info": "#dbeafe",
}


def risk_matrix(
    cells: dict[tuple[int, int], int], *, theme: Theme = DEFAULT_THEME, cell: int = 52
) -> str:
    """The five-by-five likelihood (rows, 5 at the top) by impact (columns) heat map."""
    from codekavach.report.model.finding_view import risk_band  # noqa: PLC0415

    left, top = 70, 10
    size_w = left + 5 * cell + 10
    size_h = top + 5 * cell + 46
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Risk matrix" '
        f'width="{size_w}" height="{size_h}" viewBox="0 0 {size_w} {size_h}" class="ck-chart">',
        "<title>Risk matrix: likelihood by impact</title>",
    ]
    for row in range(5):
        likelihood = 5 - row
        y = top + row * cell
        parts.append(
            f'<text x="{left - 8}" y="{y + cell / 2 + 4}" text-anchor="end" {_FONT} '
            f'font-size="11" class="mut" fill="{theme.muted}">{likelihood}</text>'
        )
        for col in range(5):
            impact = col + 1
            x = left + col * cell
            band = risk_band(likelihood * impact)
            count = cells.get((likelihood, impact), 0)
            parts.append(
                f'<rect x="{x + 1}" y="{y + 1}" width="{cell - 2}" height="{cell - 2}" rx="4" '
                f'fill="{_BAND_FILL[band]}"><title>Likelihood {likelihood}, impact {impact} '
                f"({band}): {count} finding(s)</title></rect>"
            )
            if count:
                parts.append(
                    f'<circle cx="{x + cell / 2}" cy="{y + cell / 2}" r="14" '
                    f'fill="{theme.severity(band)}"/>'
                    f'<text x="{x + cell / 2}" y="{y + cell / 2 + 4}" text-anchor="middle" '
                    f'{_FONT} font-size="12" font-weight="700" fill="#ffffff">{count}</text>'
                )
    base = top + 5 * cell
    parts.extend(
        f'<text x="{left + col * cell + cell / 2}" y="{base + 16}" text-anchor="middle" '
        f'{_FONT} font-size="11" class="mut" fill="{theme.muted}">{col + 1}</text>'
        for col in range(5)
    )
    parts.append(
        f'<text x="{left + 5 * cell / 2}" y="{base + 36}" text-anchor="middle" {_FONT} '
        f'font-size="11" font-weight="600" class="ink" fill="{theme.ink}">Impact</text>'
        f'<text x="14" y="{top + 5 * cell / 2}" text-anchor="middle" {_FONT} font-size="11" '
        f'font-weight="600" class="ink" fill="{theme.ink}" '
        f'transform="rotate(-90 14 {top + 5 * cell / 2})">'
        "Likelihood</text></svg>"
    )
    return "".join(parts)
