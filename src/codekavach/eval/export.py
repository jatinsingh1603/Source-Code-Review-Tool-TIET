# ruff: noqa: PLC0415, D103, E501
"""Results exports: Markdown summary, LaTeX table and figures (#279, #283).

Figures are SVG written here (no dependency), plus a PNG when matplotlib is importable.
"""

from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

PALETTE = ("#2563eb", "#16a34a", "#d97706", "#dc2626", "#7c3aed", "#0891b2")


def _pct(x: float) -> str:
    return f"{100 * x:.1f}"


def _tex(text: str) -> str:
    return (
        text.replace("\\", "")
        .replace("_", r"\_")
        .replace("&", r"\&")
        .replace("%", r"\%")
        .replace("#", r"\#")
        .replace("@", "@")
    )


def detection_markdown(results: dict[str, Any]) -> str:
    ds = results["dataset"]
    lines = [
        f"# Detection evaluation: {ds['name']}",
        "",
        f"Dataset layout `{ds['layout']}`, {ds['vulnerabilities']} labelled vulnerabilities, "
        f"{ds['controls']} safe controls, synthetic: {ds['synthetic']}.",
        "",
        "| Arm | Findings | TP | FP | FN | Precision (95% CI) | Recall (95% CI) | F1 (95% CI) |",
        "| --- | ---: | ---: | ---: | ---: | --- | --- | --- |",
    ]
    for arm in results["arms"]:
        if arm.get("skipped_reason"):
            lines.append(f"| {arm['arm']} | skipped | | | | {arm['skipped_reason']} | | |")
            continue
        o = arm["overall"]
        lines.append(
            f"| {arm['arm']} | {arm['findings']} | {o['tp']} | {o['fp']} | {o['fn']} | "
            f"{_pct(o['precision'])} ({_pct(o['precision_ci'][0])}-{_pct(o['precision_ci'][1])}) | "
            f"{_pct(o['recall'])} ({_pct(o['recall_ci'][0])}-{_pct(o['recall_ci'][1])}) | "
            f"{_pct(o['f1'])} ({_pct(o['f1_ci'][0])}-{_pct(o['f1_ci'][1])}) |"
        )
    lines += ["", "Method: " + "; ".join(f"{k}: {v}" for k, v in results["method"].items()), ""]
    return "\n".join(lines)


def detection_latex(results: dict[str, Any]) -> str:
    rows = []
    for arm in results["arms"]:
        if arm.get("skipped_reason"):
            continue
        o = arm["overall"]
        rows.append(
            f"{_tex(arm['arm'])} & {o['tp']} & {o['fp']} & {o['fn']} & "
            f"{_pct(o['precision'])} & {_pct(o['recall'])} & "
            f"{_pct(o['f1'])} [{_pct(o['f1_ci'][0])}, {_pct(o['f1_ci'][1])}] \\\\"
        )
    body = "\n".join(rows)
    return (
        "\\begin{table}[t]\n\\centering\n\\begin{tabular}{lrrrrrr}\n\\hline\n"
        "Arm & TP & FP & FN & P (\\%) & R (\\%) & F1 (\\%) [95\\% CI] \\\\\n\\hline\n"
        f"{body}\n\\hline\n\\end{{tabular}}\n"
        f"\\caption{{Detection on {_tex(results['dataset']['name'])}.}}\n"
        "\\label{tab:detection}\n\\end{table}\n"
    )


def bar_chart_svg(
    title: str,
    labels: list[str],
    series: dict[str, list[float]],
    *,
    errors: dict[str, list[tuple[float, float]]] | None = None,
    y_label: str = "",
) -> str:
    """Grouped bar chart of values in [0, 1] as a self-contained SVG."""
    width, height = 720, 380
    left, right, top, bottom = 60, 20, 50, 80
    plot_w, plot_h = width - left - right, height - top - bottom
    names = list(series)
    group_w = plot_w / max(1, len(labels))
    bar_w = group_w * 0.8 / max(1, len(names))
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        'font-family="Inter,Arial,sans-serif" font-size="12">',
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
        f'<text x="{width / 2}" y="26" text-anchor="middle" font-size="15" font-weight="600">'
        f"{escape(title)}</text>",
    ]
    for tick in range(6):
        v = tick / 5
        y = top + plot_h * (1 - v)
        parts.append(
            f'<line x1="{left}" x2="{width - right}" y1="{y:.1f}" y2="{y:.1f}" stroke="#e5e7eb"/>'
        )
        parts.append(
            f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end" fill="#475569">{v:.1f}</text>'
        )
    if y_label:
        parts.append(
            f'<text x="14" y="{top + plot_h / 2}" transform="rotate(-90 14 {top + plot_h / 2})" '
            f'text-anchor="middle" fill="#475569">{escape(y_label)}</text>'
        )
    for gi, label in enumerate(labels):
        gx = left + gi * group_w + group_w * 0.1
        for si, name in enumerate(names):
            value = max(0.0, min(1.0, series[name][gi]))
            h = plot_h * value
            x = gx + si * bar_w
            parts.append(
                f'<rect x="{x:.1f}" y="{top + plot_h - h:.1f}" width="{bar_w * 0.92:.1f}" '
                f'height="{h:.1f}" fill="{PALETTE[si % len(PALETTE)]}"><title>{escape(name)} '
                f"{escape(label)}: {value:.3f}</title></rect>"
            )
            if errors and name in errors:
                lo, hi = errors[name][gi]
                cx = x + bar_w * 0.46
                y1 = top + plot_h * (1 - hi)
                y2 = top + plot_h * (1 - lo)
                parts.append(
                    f'<line x1="{cx:.1f}" x2="{cx:.1f}" y1="{y1:.1f}" y2="{y2:.1f}" stroke="#111827"/>'
                )
        parts.append(
            f'<text x="{gx + group_w * 0.4:.1f}" y="{top + plot_h + 18}" text-anchor="middle" '
            f'fill="#111827">{escape(label)}</text>'
        )
    for si, name in enumerate(names):
        lx = left + si * 150
        parts.append(
            f'<rect x="{lx}" y="{height - 30}" width="12" height="12" fill="{PALETTE[si % len(PALETTE)]}"/>'
        )
        parts.append(f'<text x="{lx + 18}" y="{height - 20}" fill="#111827">{escape(name)}</text>')
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def _png(
    svg_path: Path, labels: list[str], series: dict[str, list[float]], title: str
) -> Path | None:
    try:
        import matplotlib  # type: ignore[import-not-found,unused-ignore]

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt  # type: ignore[import-not-found,unused-ignore]
    except Exception:  # noqa: BLE001 - optional dependency
        return None
    fig, ax = plt.subplots(figsize=(7.2, 3.8))
    width = 0.8 / max(1, len(series))
    for i, (name, values) in enumerate(series.items()):
        ax.bar(
            [x + i * width for x in range(len(labels))],
            values,
            width,
            label=name,
            color=PALETTE[i % len(PALETTE)],
        )
    ax.set_xticks([x + width * (len(series) - 1) / 2 for x in range(len(labels))], labels)
    ax.set_ylim(0, 1)
    ax.set_title(title)
    ax.legend()
    png = svg_path.with_suffix(".png")
    fig.savefig(png, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return png


def write_detection_outputs(results: dict[str, Any], directory: Path) -> list[str]:
    """Write ``summary.md``, ``table.tex`` and ``f1.svg`` (and a PNG with matplotlib)."""
    written = []
    (directory / "summary.md").write_text(detection_markdown(results), encoding="utf-8")
    (directory / "table.tex").write_text(detection_latex(results), encoding="utf-8")
    arms = [a for a in results["arms"] if not a.get("skipped_reason")]
    labels = [a["arm"] for a in arms]
    series = {
        "precision": [a["overall"]["precision"] for a in arms],
        "recall": [a["overall"]["recall"] for a in arms],
        "F1": [a["overall"]["f1"] for a in arms],
    }
    errors = {"F1": [tuple(a["overall"]["f1_ci"]) for a in arms]}
    title = f"Detection quality on {results['dataset']['name']}"
    svg = directory / "f1.svg"
    svg.write_text(
        bar_chart_svg(title, labels, series, errors=errors, y_label="score"), encoding="utf-8"
    )
    written += ["summary.md", "table.tex", "f1.svg"]
    if _png(svg, labels, series, title):
        written.append("f1.png")
    return written
