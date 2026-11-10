"""Polished paper figures generated from retained source CSVs.

The reporting module keeps the audit source files and manifest metadata.  This
module is only a presentation layer: it reads the generated source CSVs and
writes presentation figures without changing their retained numerical sources.
"""

from __future__ import annotations

import argparse
import csv
import html
import math
import statistics
import sys
import subprocess
from collections import Counter, defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

from .baselines import (
    ADMISSION_FIRST_MODE,
    EvaluationRole,
    load_mode_registry,
    mode_execution_order_key,
    normalize_mode_id,
)


ROOT = Path(__file__).resolve().parents[1]
FIG_ROOT = ROOT / "results" / "figures"

INK = "#1f2933"
MUTED = "#64748b"
GRID = "#d7dee8"
GREEN = "#2a9d8f"
BLUE = "#3a6ea5"
LIGHT_BLUE = "#d9e7f5"
ORANGE = "#e9a03b"
RED = "#c94c4c"
PURPLE = "#7b6bb7"
GRAY = "#8a94a6"
PAPER = "#ffffff"

PAPER_PANEL_WIDTH = 560
PAPER_PANEL_HEIGHT = 260
# Retained compact renderer scale: SVG pixels -> PDF points -> 0.49 text width.
PAPER_POINT_SCALE = 0.75 * 0.58849

TAXONOMY_FIGURES = (
    "evaluation-composite",
    "fig5_e5_template_regret",
    "fig8_e9_overhead",
    "tab2_e10_diversity",
    "tab2_e10_diversity_full_seed42",
)


@lru_cache(maxsize=1)
def _mode_registry() -> dict[str, Any]:
    return load_mode_registry(ROOT)


def _canonical_mode(value: str) -> str:
    """Normalize a retained source-file mode without rewriting that source."""

    return normalize_mode_id(value)


def _mode_label(value: str) -> str:
    try:
        mode = _canonical_mode(value)
        return _mode_registry()[mode].paper_label
    except (KeyError, ValueError):
        return value.replace("_", " ").replace("-", " ").title()


def read_rows(name: str) -> list[dict[str, str]]:
    path = FIG_ROOT / name / f"{name}_source.csv"
    with path.open(newline="", encoding="utf-8") as fh:
        rows = [dict(row) for row in csv.DictReader(fh)]
    for row in rows:
        legacy_mode = row.get("mode", "")
        if not legacy_mode:
            continue
        mode = _canonical_mode(legacy_mode)
        spec = _mode_registry()[mode]
        row["mode"] = mode
        row["evaluation_role"] = spec.evaluation_role
    return rows


def fnum(value: Any, default: float | None = None) -> float | None:
    try:
        if value in ("", None):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def esc(text: Any) -> str:
    return html.escape(str(text), quote=True)


def family_label(value: str, *, experiment: str | None = None) -> str:
    # E3 (including its SF10 follow-ups) uses availability priority, whereas
    # the same legacy wire ID has different roles in E4/E9/E10.
    if value == "local-greedy" and experiment == "E3":
        return "IndexPriority"
    mapping = {
        "auth-index-enum-only": "Authorization index",
        "auth_index_enum_v1": "Authorization index",
        "auth-index": "Authorization index",
        "auth-view-only": "Authorization view",
        "auth_view_scan_v1": "Authorization view",
        "barrier-only": "Security barrier",
        "barrier_filter_v1": "Security barrier",
        ADMISSION_FIRST_MODE: "AdmissionFirst",
        "guard-mandatory-discharge": "Guard with residual",
        "guard_candidate_plus_residual_v1": "Guard with residual",
        "injection-only": "Query with policy predicate",
        "safe_predicate_injection_v1": "Query with policy predicate",
        "mav-only": "Materialized view",
        "mav_scan_v1": "Materialized view",
        "strong-auth-index": "Keyed authorization index",
        "strong_auth_index_keyed_v1": "Keyed authorization index",
        "hybrid_intersect_v1": "Index intersection",
        "hybrid": "Index intersection",
        "ordinary_first_exact_check_v1": "Ordinary predicate first",
        "adaptive_choice": "AdmissionFirst",
        "local-greedy": "Local greedy",
        "native-pg-rls": "NativePG-RLS",
        "native-pg-rls-physical-design": "NativePG-RLS + physical design",
        "security-barrier": "Security barrier",
    }
    if value in mapping:
        return mapping[value]
    return _mode_label(value)


def family_color(label: str) -> str:
    palette = {
        "Authorization index": "#2f6f9f",
        "Authorization view": "#7b6bb7",
        "Security barrier": "#d27d2d",
        "AdmissionFirst": GREEN,
        "Guard with residual": "#b05f6d",
        "Query with policy predicate": "#5f8f3f",
        "Materialized view": "#8a6d3b",
        "Keyed authorization index": "#3f83cc",
        "Index intersection": "#5b7f95",
        "NativePG-RLS": GRAY,
        "NativePG-RLS + physical design": "#9aa6b2",
        "Local greedy": RED,
        "IndexPriority": RED,
        "Ordinary predicate first": "#4b5563",
    }
    return palette.get(label, BLUE)


class Svg:
    def __init__(self, width: int, height: int) -> None:
        self.width = width
        self.height = height
        self.parts: list[str] = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'viewBox="0 0 {width} {height}">',
            f'<rect width="{width}" height="{height}" fill="{PAPER}"/>',
        ]

    def text(
        self,
        x: float,
        y: float,
        text: Any,
        *,
        size: float = 13,
        weight: str = "400",
        fill: str = INK,
        anchor: str = "start",
        family: str = "Arial, Helvetica, sans-serif",
        rotate: float = 0,
    ) -> None:
        transform = f' transform="rotate({rotate:g} {x:.1f} {y:.1f})"' if rotate else ""
        self.parts.append(
            f'<text x="{x:.1f}" y="{y:.1f}" font-family="{family}" font-size="{size}" '
            f'font-weight="{weight}" fill="{fill}" text-anchor="{anchor}"{transform}>{esc(text)}</text>'
        )

    def rect(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        *,
        fill: str = "none",
        stroke: str = "none",
        sw: float = 1,
        rx: float = 0,
    ) -> None:
        self.parts.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" '
            f'rx="{rx:.1f}" fill="{fill}" stroke="{stroke}" stroke-width="{sw:.1f}"/>'
        )

    def line(self, x1: float, y1: float, x2: float, y2: float, *, stroke: str = GRID, sw: float = 1) -> None:
        self.parts.append(
            f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
            f'stroke="{stroke}" stroke-width="{sw:.1f}"/>'
        )

    def diagonal_hatch(
        self, x: float, y: float, w: float, h: float, *,
        step: float = 8, stroke: str = "#f4b9b9", sw: float = 0.9,
    ) -> None:
        """Draw diagonal vector strokes trimmed to a rectangular fill."""
        fmt = lambda value: f"{value:.1f}".rstrip("0").rstrip(".")
        segments: list[str] = []
        start = x - step
        while start < x + w:
            left = max(x, start)
            right = min(x + w, start + h)
            if right > left:
                y_left = y + h - (left - start)
                y_right = y + h - (right - start)
                segments.append(
                    f"M{fmt(left)} {fmt(y_left)} L{fmt(right)} {fmt(y_right)}"
                )
            start += step
        path_data = " ".join(segments)
        self.parts.append(
            f'<path d="{path_data}" fill="none" stroke="{stroke}" stroke-width="{sw:g}"/>'
        )

    def polyline(self, points: Iterable[tuple[float, float]], *, stroke: str = BLUE, sw: float = 2) -> None:
        pts = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
        self.parts.append(f'<polyline points="{pts}" fill="none" stroke="{stroke}" stroke-width="{sw:.1f}"/>')

    def circle(self, x: float, y: float, r: float, *, fill: str = BLUE, stroke: str = "none", sw: float = 1) -> None:
        self.parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r:.1f}" fill="{fill}" stroke="{stroke}" stroke-width="{sw:g}"/>')

    def save(self, path: Path) -> None:
        self.parts.append("</svg>")
        path.write_text("\n".join(self.parts), encoding="utf-8")


class PaperPanel(Svg):
    """Draw in final manuscript points while retaining the existing SVG canvas."""

    def __init__(self) -> None:
        super().__init__(PAPER_PANEL_WIDTH, PAPER_PANEL_HEIGHT)
        self.parts.append(f'<g transform="scale({1 / PAPER_POINT_SCALE:.10f})">')

    def save(self, path: Path) -> None:
        self.parts.append("</g>")
        super().save(path)


@lru_cache(maxsize=1)
def check_paper_fonts() -> None:
    """Fail before export if font substitution invalidates the compact layout."""
    for style in ("Regular", "Bold"):
        try:
            resolved = subprocess.run(
                ["fc-match", "-f", "%{family}\n%{style}\n%{file}\n", f"Arial:style={style}"],
                check=True, capture_output=True, text=True,
            ).stdout.splitlines()
        except (OSError, subprocess.CalledProcessError) as exc:
            raise RuntimeError("Paper figures require fontconfig and Arial Regular/Bold.") from exc
        if len(resolved) != 3 or resolved[0] != "Arial" or style not in resolved[1].split(","):
            raise RuntimeError(
                f"Arial {style} required by the paper layout; fontconfig resolved {resolved!r}. "
                "Install Arial or recalculate the layout for the replacement font."
            )
        if not Path(resolved[2]).is_file():
            raise RuntimeError(f"Resolved Arial font file does not exist: {resolved[2]}")


def write_svg_pdf(name: str, svg: Svg, *, output_stem: str | None = None) -> None:
    out_dir = FIG_ROOT / name
    stem = output_stem or name
    svg_path = out_dir / f"{stem}.svg"
    pdf_path = out_dir / f"{stem}.pdf"
    raw_pdf_path = out_dir / f"{stem}.raw.pdf"
    if isinstance(svg, PaperPanel):
        check_paper_fonts()
    svg.save(svg_path)
    subprocess.run(["rsvg-convert", "-f", "pdf", "-o", str(raw_pdf_path), str(svg_path)], check=True)
    subprocess.run(
        [
            "gs",
            "-q",
            "-dSAFER",
            "-dBATCH",
            "-dNOPAUSE",
            "-dNoOutputFonts",
            "-dPDFSETTINGS=/prepress",
            "-sDEVICE=pdfwrite",
            f"-sOutputFile={pdf_path}",
            str(raw_pdf_path),
        ],
        check=True,
    )
    raw_pdf_path.unlink(missing_ok=True)


def draw_pill(svg: Svg, x: float, y: float, text: str, color: str, width: float = 110) -> None:
    svg.rect(x, y, width, 24, fill=color, rx=12)
    svg.text(x + width / 2, y + 16, text, size=11, weight="700", fill="#ffffff", anchor="middle")


def legacy_fig2_contract_matrix(*, compact: bool = False) -> None:
    """Historical label-derived diagnostic figure; excluded from active renders."""
    rows = read_rows("fig2_contract_matrix")
    admission_first_rows = [r for r in rows if r["mode"] == ADMISSION_FIRST_MODE]
    control_rows = [r for r in rows if r["mode"] != ADMISSION_FIRST_MODE]
    violation_rows = [
        row
        for row in control_rows
        if row["evaluation_role"] == EvaluationRole.CONTRACT_VIOLATION_CONTROL.value
    ]
    conservative_rows = [
        row
        for row in control_rows
        if row["evaluation_role"] == EvaluationRole.CONSERVATIVE_CONTROL.value
    ]
    if (len(admission_first_rows), len(violation_rows), len(conservative_rows)) != (21, 15, 1):
        raise ValueError(
            "Figure 3(a) taxonomy must remain 21 AdmissionFirst cases, "
            "15 contract-violation controls, and one conservative control"
        )
    admission_first_wrong = sum(1 for r in admission_first_rows if r["status"] in {"wrong_result", "unsafe_observation"})
    admission_first_observations = sum(int(fnum(r.get("unauthorized_observations"), 0) or 0) for r in admission_first_rows)
    admission_first_counts = Counter(r["status"] for r in admission_first_rows)
    ctrl_counts = Counter(r["status"] for r in control_rows)

    if compact:
        svg = PaperPanel()
        correct_color = "#267f75"
        reject_color = "#718096"
        svg.rect(5, 3, 237, 17, fill="#edf7f3", stroke="#c8e3d8", sw=0.5, rx=3)
        svg.text(
            123.5, 14,
            f"AF: {admission_first_counts['wrong_result']} incorrect results; {admission_first_observations} unauthorized observations",
            size=7, fill="#236c58", anchor="middle",
        )
        groups = [
            ("AF", "cases", admission_first_counts,
             [("pass", correct_color), ("expected_reject", reject_color),
              ("wrong_result", RED), ("unsafe_observation", ORANGE)]),
            ("Controls", "controls", ctrl_counts,
             [("wrong_result", RED), ("unsafe_observation", ORANGE), ("pass", correct_color)]),
        ]
        for index, (label, unit, counts, statuses) in enumerate(groups):
            y = 34 + index * 27
            total = sum(counts.values())
            svg.text(5, y + 9, label, size=7)
            x = 77.0
            labels = []
            for status, color in statuses:
                count = counts[status]
                if not count:
                    continue
                width = 125 * count / total
                svg.rect(x, y, width, 13, fill=color)
                if status == "wrong_result":
                    svg.diagonal_hatch(x, y, width, 13)
                labels.append((x + width / 2, str(count), INK if status == "unsafe_observation" else PAPER))
                x += width
            # All segments precede all labels; even the one-case segment fits a digit.
            for center, count, color in labels:
                svg.text(center, y + 9, count, size=6.5, weight="700", fill=color, anchor="middle")
            svg.text(211, y + 9, f"{total} {unit}", size=6.5, fill=INK)
        legend = [
            ("correct result", correct_color), ("Rejected", reject_color),
            ("incorrect result", RED), ("unauthorized observation", ORANGE),
        ]
        for index, (label, color) in enumerate(legend):
            x, y = (5 + (index % 2) * 109, 92 + (index // 2) * 13)
            svg.rect(x, y - 5, 5.5, 5.5, fill=color, rx=0.6)
            if label == "incorrect result":
                svg.diagonal_hatch(x + 0.8, y - 4.4, 4.1, 4.1)
            svg.text(x + 9, y, label, size=6.5, fill=INK)
        write_svg_pdf("fig2_contract_matrix", svg, output_stem="fig2_contract_matrix-crop")
        return

    svg = Svg(560, 330)
    svg.text(24, 34, "Validation outcomes", size=18, weight="700")
    svg.text(24, 55, "Outcomes for AdmissionFirst and diagnostic controls.", size=12, fill=MUTED)
    pill_y = 78
    group_y = 134
    group_step = 82
    legend_y = 292
    draw_pill(svg, 24, pill_y, f"incorrect or unsafe outcomes = {admission_first_wrong}", GREEN, 218)
    draw_pill(svg, 255, pill_y, f"unauthorized observations = {admission_first_observations}", GREEN, 205)

    groups = [
        ("AdmissionFirst", admission_first_counts, [("pass", GREEN), ("expected_reject", GRAY), ("wrong_result", RED), ("unsafe_observation", ORANGE)]),
        ("Diagnostic controls", ctrl_counts, [("wrong_result", RED), ("unsafe_observation", ORANGE), ("pass", GREEN)]),
    ]
    x0, y0, bar_w = 180, group_y, 270
    for idx, (label, counts, items) in enumerate(groups):
        y = y0 + idx * group_step
        svg.text(24, y + 18, label, size=13, weight="700")
        svg.line(x0, y + 24, x0 + bar_w, y + 24, stroke="#eef2f7")
        x = x0
        total = sum(counts.values())
        for status, color in items:
            count = counts.get(status, 0)
            if count <= 0:
                continue
            w = bar_w * count / max(total, 1)
            svg.rect(x, y, w, 30, fill=color)
            svg.text(x + w / 2, y + 20, str(count), size=11, weight="700", fill=INK if status == "unsafe_observation" else PAPER, anchor="middle")
            x += w
        denominator = "cases" if label == "AdmissionFirst" else "controls"
        svg.text(x0 + bar_w + 24, y + 20, f"{total} {denominator}", size=11, fill=MUTED)

    legend = [("correct result", GREEN), ("expected rejection", GRAY), ("incorrect result", RED), ("unauthorized observation", ORANGE)]
    legend_xs = (24, 156, 288, 420)
    y = legend_y
    for x, (label, color) in zip(legend_xs, legend):
        svg.rect(x, y - 10, 11, 11, fill=color, rx=2)
        svg.text(x + 16, y, label, size=10, fill=MUTED)
    write_svg_pdf(
        "fig2_contract_matrix",
        svg,
        output_stem=None,
    )


def legacy_fig7_sigma_ablation(*, compact: bool = False) -> None:
    """Historical fixture-label matrix; excluded from active renders."""
    rows = read_rows("fig7_sigma_ablation")
    ablated = [r for r in rows if r["mode"] != ADMISSION_FIRST_MODE]
    labels = {
        "NoRIDMatProps": "RID/materialization",
        "NoSafetyLevel": "Expression safety",
        "NoContextScope": "Context scope",
        "NoFreshness": "Freshness",
        "NoDomain": "Per-occurrence coverage",
        "NoBranchLineage": "Branch lineage",
        "NoResidual": "Residual tracking",
        "NoPhysProps": "Physical properties",
    }
    colors = {
        "wrong_result": RED,
        "unsafe_observation": ORANGE,
        "expected_reject": GRAY,
        "pass": GREEN,
    }
    texts = {
        "wrong_result": "incorrect result",
        "unsafe_observation": "unauthorized observation",
        "expected_reject": "expected rejection",
        "pass": "correct result",
    }

    case_labels = {
        "E6b_join_rid_intersection": "join RID intersection",
        "E6b_audit_after_candidate": "audit after candidate",
        "E6b_cross_purpose_dashboard": "cross-purpose query",
        "E6b_revocation_refresh": "revocation refresh",
        "E6b_self_join_branch_domain": "self-join branch",
        "E6b_union_distinct_branch": "union branch",
        "E6b_guard_join_residual": "guard-join residual",
        "E6b_ordered_export_cost": "ordered export",
    }
    if compact:
        order = ["NoFreshness", "NoSafetyLevel", "NoRIDMatProps", "NoContextScope",
                 "NoDomain", "NoBranchLineage", "NoResidual", "NoPhysProps"]
        if len(ablated) != 8 or {row["component"] for row in ablated} != set(order):
            raise ValueError("The paper matrix requires the eight declared component ablations")
        compact_labels = {
            "NoRIDMatProps": "Row IDs and materialization",
            "NoSafetyLevel": "Expression safety",
            "NoContextScope": "Context scope",
            "NoFreshness": "Freshness",
            "NoDomain": "Coverage of each occurrence",
            "NoBranchLineage": "Branch origins",
            "NoResidual": "Tracking pending checks",
            "NoPhysProps": "Order information",
        }
        svg = PaperPanel()
        svg.text(5, 12, "Removed item", size=7)
        centers = {"wrong_result": 156.5, "unsafe_observation": 194, "pass": 229}
        for x, top, bottom in [(156.5, "Incorrect", "result"),
                               (194, "Unauthorized", "observation"), (229, "Correct", "result")]:
            svg.text(x, 8, top, size=7, anchor="middle")
            svg.text(x, 16.5, bottom, size=7, anchor="middle")
        svg.line(5, 20, 242, 20, stroke="#bdc7d0", sw=0.5)
        for index, row in enumerate(sorted(ablated, key=lambda row: order.index(row["component"]))):
            y = 28 + 11 * index
            component = compact_labels[row["component"]]
            svg.parts.append(
                f'<text x="5" y="{y}" font-family="Arial, Helvetica, sans-serif" '
                f'font-size="7" font-weight="400" fill="{INK}">{esc(component)}</text>'
            )
            status = row["status"]
            color = "#267f75" if status == "pass" else colors[status]
            svg.circle(centers[status], y - 2.5, 2.1, fill=color)
            svg.line(5, y + 3, 242, y + 3, stroke="#e6eaee", sw=0.35)
        write_svg_pdf("fig7_sigma_ablation", svg, output_stem="fig7_sigma_ablation-crop")
        return

    svg = Svg(560, 370)
    svg.text(24, 34, "Delivered-state ablation results", size=18, weight="700")
    svg.text(24, 55, "Outcome after removal of one delivered-state component.", size=12, fill=MUTED)
    header_y, row_y, row_step = 90, 112, 28
    result_x, result_w, case_x = 292, 154, 456
    svg.text(24, header_y, "Removed component", size=11, weight="700", fill=MUTED)
    svg.text(result_x, header_y, "Observed result", size=11, weight="700", fill=MUTED)
    svg.text(case_x, header_y, "Case", size=11, weight="700", fill=MUTED)
    y = row_y
    for row in ablated:
        component = labels.get(row["component"], row["component"])
        status = row["status"]
        color = colors.get(status, BLUE)
        svg.line(24, y + 24, 522, y + 24, stroke="#edf1f6")
        svg.text(24, y + 16, component, size=12)
        svg.rect(result_x, y - 2, result_w, 24, fill=color, rx=12)
        svg.text(result_x + result_w / 2, y + 15, texts.get(status, status), size=9.5, weight="700", fill="#ffffff", anchor="middle")
        case = case_labels.get(row["case_id"], row["case_id"])
        svg.text(case_x, y + 15, case, size=9.5, fill=MUTED)
        y += row_step
    write_svg_pdf("fig7_sigma_ablation", svg)


def fig3_e2_phase_diagram(*, compact: bool = False) -> None:
    rows = [
        r
        for r in read_rows("fig3_e2_phase_diagram")
        if r["status"] == "pass"
        and fnum(r["total_ms_median"], 0)
        and r["mode"] not in {ADMISSION_FIRST_MODE, "template-oracle"}
    ]
    by_mode: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        value = fnum(row["total_ms_median"], None)
        if value is not None and value > 0:
            by_mode[row["mode"]].append(value)

    summaries = []
    for mode, values in by_mode.items():
        ordered = sorted(values)
        summaries.append(
            (
                family_label(mode),
                ordered[0],
                statistics.median(ordered),
                ordered[-1],
                len(ordered),
            )
        )
    summaries.sort(key=lambda item: item[2])

    if compact:
        svg = PaperPanel()
        plot_left, plot_right = 95.0, 207.0
        log_min, log_max = math.log10(0.1), math.log10(200)

        def median_x(value: float) -> float:
            return plot_left + (math.log10(value) - log_min) / (log_max - log_min) * (plot_right - plot_left)

        svg.text(5, 10, "Enforcement family", size=7)
        svg.text(230, 8, "Passing", size=6.5, anchor="middle")
        svg.text(230, 15.5, "cases", size=6.5, anchor="middle")
        for tick in (0.1, 1, 10, 100):
            x = median_x(tick)
            svg.text(x, 14, str(tick), size=6.5, anchor="middle")
            svg.line(x, 20, x, 102, stroke="#e6eaee", sw=0.5)
        for index, (label, _, median, _, count) in enumerate(summaries):
            y = 26 + 12 * index
            svg.text(5, y + 2.3, label, size=7)
            svg.circle(median_x(median), y, 2, fill=BLUE)
            svg.text(230, y + 2.3, f"{count}/8", size=7, anchor="middle")
        svg.text(151, 113, "Latency (ms, log scale)", size=7, anchor="middle")
        write_svg_pdf("fig3_e2_phase_diagram", svg, output_stem="fig3_e2_phase_diagram-crop")
        return

    svg = Svg(600, 370)
    svg.text(24, 34, "Fixed-enforcement latency ranges", size=18, weight="700")
    svg.text(
        24,
        55,
        "Min–median–max end-to-end latency across eight declared cases (log scale).",
        size=12,
        fill=MUTED,
    )

    plot_x, plot_w = (178, 344)
    plot_y, row_h = (94, 34)
    count_x = 548
    log_min, log_max = math.log10(0.1), math.log10(200.0)

    def x_for(value: float) -> float:
        return plot_x + (math.log10(value) - log_min) / (log_max - log_min) * plot_w

    for tick in (0.1, 1.0, 10.0, 100.0):
        x = x_for(tick)
        svg.line(x, plot_y - 14, x, plot_y + row_h * len(summaries) - 4, stroke="#e7edf4")
        svg.text(x, plot_y - 22, f"{tick:g} ms", size=9, fill=MUTED, anchor="middle")
    svg.text(count_x, plot_y - 22, "Passing cases", size=9, weight="700", fill=MUTED, anchor="middle")

    for index, (label, minimum, median, maximum, count) in enumerate(summaries):
        y = plot_y + index * row_h
        color = family_color(label)
        svg.text(24, y + 7, label, size=11, weight="700")
        svg.line(x_for(minimum), y + 3, x_for(maximum), y + 3, stroke=color, sw=5)
        svg.circle(x_for(median), y + 3, 6, fill=PAPER, stroke=color)
        svg.circle(x_for(median), y + 3, 3, fill=color)
        svg.text(count_x, y + 7, f"{count}/8", size=10, weight="700", fill=INK, anchor="middle")

    svg.text(
        24,
        350,
        "The line denotes the observed range; the point denotes the median. Case counts depend on artifact availability.",
        size=10,
        fill=MUTED,
    )
    write_svg_pdf(
        "fig3_e2_phase_diagram",
        svg,
        output_stem=None,
    )


def fig3_e2_phase_diagram_legacy_compact() -> None:
    """Refresh the retained 600x278 compact asset with reader-facing case labels."""

    rows = [
        row
        for row in read_rows("fig3_e2_phase_diagram")
        if row["status"] == "pass"
        and fnum(row["total_ms_median"], 0)
        and row["mode"] not in {ADMISSION_FIRST_MODE, "template-oracle"}
    ]
    by_mode: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        value = fnum(row["total_ms_median"], None)
        if value is not None and value > 0:
            by_mode[row["mode"]].append(value)

    summaries = []
    for mode, values in by_mode.items():
        ordered = sorted(values)
        summaries.append(
            (
                family_label(mode),
                ordered[0],
                statistics.median(ordered),
                ordered[-1],
                len(ordered),
            )
        )
    summaries.sort(key=lambda item: item[2])

    svg = Svg(600, 278)
    plot_x, plot_w = 178.0, 344.0
    log_min, log_max = math.log10(0.1), math.log10(200.0)

    def x_for(value: float) -> float:
        return plot_x + (math.log10(value) - log_min) / (log_max - log_min) * plot_w

    for tick in (0.1, 1.0, 10.0, 100.0):
        x = x_for(tick)
        svg.line(x, 28, x, 262, stroke="#e7edf4")
        svg.text(x, 20, f"{tick:g} ms", size=9, fill=MUTED, anchor="middle")
    svg.text(548, 20, "Passing cases", size=9, weight="700", fill=MUTED, anchor="middle")

    for index, (label, minimum, median, maximum, count) in enumerate(summaries):
        y = 45 + 32 * index
        color = family_color(label)
        svg.text(24, y + 4, label, size=11, weight="700")
        svg.line(x_for(minimum), y, x_for(maximum), y, stroke=color, sw=5)
        svg.circle(x_for(median), y, 6, fill=PAPER, stroke=color)
        svg.circle(x_for(median), y, 3, fill=color)
        svg.text(548, y + 4, f"{count}/8", size=10, weight="700", fill=INK, anchor="middle")

    write_svg_pdf(
        "fig3_e2_phase_diagram",
        svg,
        output_stem="fig3_e2_phase_diagram_compact",
    )


def fig4_e3_speedup(*, compact: bool = False) -> None:
    rows = [r for r in read_rows("fig4_e3_speedup") if r["status"] == "pass"]
    by_cell: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_cell[(row["query_id"], row["policy_config_id"])].append(row)

    slowdowns: list[tuple[str, str, float, str]] = []
    winners: Counter[str] = Counter()
    for (query, policy), group in by_cell.items():
        valid = [r for r in group if fnum(r["total_ms_median"], 0) and fnum(r["total_ms_median"], 0) > 0]
        if not valid:
            continue
        best = min(
            valid,
            key=lambda r: (
                fnum(r["total_ms_median"], math.inf) or math.inf,
                mode_execution_order_key(r["mode"]),
            ),
        )
        winners[family_label(best["mode"], experiment="E3")] += 1
        admission_first = next((r for r in valid if r["mode"] == ADMISSION_FIRST_MODE), None)
        if admission_first is None:
            continue
        slowdown = (fnum(admission_first["total_ms_median"], 0) or 0) / (fnum(best["total_ms_median"], 1) or 1)
        slowdowns.append((query, policy, slowdown, family_label(best["mode"], experiment="E3")))
    slowdowns.sort(key=lambda item: (item[2], item[0], item[1]))

    if compact:
        if len(slowdowns) != 33:
            raise ValueError(f"The paper layout requires 33 mixed-workload cases; got {len(slowdowns)}")
        svg = PaperPanel()
        x_first, x_last = 35.0, 238.1658
        y_top, y_one, axis_bottom = 12.0, 92.0, 95.0

        def rank_x(rank: float) -> float:
            return x_first + (rank - 1) * (x_last - x_first) / 32

        def ratio_y(ratio: float) -> float:
            if not 1 <= ratio <= 1.7:
                raise ValueError(f"Ratio {ratio:g} is outside the paper panel's continuous scale")
            return y_one - (ratio - 1) / 0.7 * (y_one - y_top)

        exact = sum(item[2] == 1 for item in slowdowns)
        near = sum(1 < item[2] <= 1.01 for item in slowdowns)
        losses = len(slowdowns) - exact - near
        for start, end, label in [
            (1, exact, f"{exact} fastest"),
            (exact + 1, exact + near, f"{near} within 1%"),
            (exact + near + 1, 33, f"{losses} over 1% slower"),
        ]:
            svg.text(rank_x((start + end) / 2), 6.5, label, size=6.5, anchor="middle")
            svg.line(rank_x(start), 9.5, rank_x(end), 9.5, stroke="#bdc7d0", sw=0.45)
        for tick in (1.0, 1.2, 1.4, 1.6):
            y = ratio_y(tick)
            svg.line(32, y, 241.1658, y, stroke="#c8d0d8" if tick == 1 else "#e7ebef", sw=0.5)
            svg.text(28, y + 2.1, f"{tick:.2f}", size=6.5, fill=INK, anchor="end")
        svg.line(32, y_top, 32, axis_bottom, stroke="#9ca9b5", sw=0.5)
        svg.line(32, axis_bottom, 241.1658, axis_bottom, stroke="#9ca9b5", sw=0.5)
        svg.text(8.5, 52, "AF / fastest mode", size=7, anchor="middle", rotate=-90)
        for rank in (1, 8, 13, 20, 26, 33):
            x = rank_x(rank)
            svg.line(x, axis_bottom, x, axis_bottom + 2, stroke="#9ca9b5", sw=0.5)
            svg.text(x, 104, str(rank), size=6.5, anchor="middle")
        svg.text(136.5, 113, "Cases ordered by slowdown", size=7, anchor="middle")
        for rank, (_, _, ratio, _) in enumerate(slowdowns, start=1):
            # Radius 1.7 plus a 0.6-point stroke gives a four-point outer diameter.
            svg.circle(rank_x(rank), ratio_y(ratio), 1.7, fill=BLUE if ratio == 1 else PAPER, stroke=BLUE, sw=0.6)
        write_svg_pdf("fig4_e3_speedup", svg, output_stem="fig4_e3_speedup-crop")
        return

    svg = Svg(560, 390)
    svg.text(24, 34, "Mixed-workload latency distribution", size=18, weight="700")
    svg.text(24, 55, "Per-case comparison with the fastest policy-enforcement mode.", size=12, fill=MUTED)

    marker_shapes = {
        "Query with policy predicate": "triangle",
        "Security barrier": "square",
        "AdmissionFirst": "circle",
        "NativePG-RLS": "diamond",
    }

    def draw_family_marker(
        x: float,
        y: float,
        label: str,
        *,
        fill: str | None = None,
        radius: float = 3.0,
    ) -> None:
        color = fill or family_color(label)
        shape = marker_shapes.get(label, "circle")
        if shape == "square":
            svg.rect(x - radius, y - radius, 2 * radius, 2 * radius, fill=color)
        elif shape == "triangle":
            points = (
                f"{x:.1f},{y - 1.15 * radius:.1f} "
                f"{x - radius:.1f},{y + radius:.1f} "
                f"{x + radius:.1f},{y + radius:.1f}"
            )
            svg.parts.append(f'<polygon points="{points}" fill="{color}"/>')
        elif shape == "diamond":
            points = (
                f"{x:.1f},{y - 1.15 * radius:.1f} "
                f"{x + 1.15 * radius:.1f},{y:.1f} "
                f"{x:.1f},{y + 1.15 * radius:.1f} "
                f"{x - 1.15 * radius:.1f},{y:.1f}"
            )
            svg.parts.append(f'<polygon points="{points}" fill="{color}"/>')
        else:
            svg.circle(x, y, radius, fill=color)

    # Distribution strip.
    x0, y0, w, h = (46, 104, 300, 130)
    heading_y = 88
    ratio_heading = "AdmissionFirst / fastest policy-enforcement mode"
    svg.text(x0, heading_y, ratio_heading, size=11, weight="700", fill=MUTED)
    for tick in [1.00, 1.02, 1.04, 1.06]:
        x = x0 + (tick - 1.0) / 0.06 * w
        svg.line(x, y0, x, y0 + h, stroke="#e6ebf2")
        tick_label = "≥1.06" if math.isclose(tick, 1.06) else f"{tick:.2f}"
        svg.text(x, y0 + h + 17, tick_label, size=9, fill=MUTED, anchor="middle")
    svg.line(x0, y0 + h, x0 + w, y0 + h, stroke=GRID)
    for idx, (_, policy, slowdown, winner) in enumerate(slowdowns):
        x = x0 + min(max((slowdown - 1.0) / 0.06, 0), 1) * w
        y = y0 + 8 + (idx % 11) * 10 + (0 if policy == "cheap_tenant_sargable" else (3 if policy == "group_acl_expensive" else 6))
        draw_family_marker(x, y, winner)
    svg.text(x0, y0 + h + 36, "Each point represents one query-policy case; color identifies the lowest-latency family.", size=9, fill=MUTED)

    # Winner counts.
    x1, y1 = (360, 96)
    svg.text(x1, heading_y, "Count by lowest-latency family", size=11, weight="700", fill=MUTED)
    max_count = max(winners.values() or [1])
    for i, (label, count) in enumerate(winners.most_common()):
        row_step = 28
        y = y1 + i * row_step
        svg.text(x1, y + 14, label, size=9.5)
        bar = 52 * count / max_count
        svg.rect(x1 + 128, y + 2, bar, 16, fill=family_color(label), rx=3)
        draw_family_marker(x1 + 134.5, y + 10, label, fill="#ffffff", radius=3.2)
        svg.text(x1 + 128 + bar + 4, y + 15, str(count), size=10, fill=MUTED)

    vals = [v for _, _, v, _ in slowdowns]
    vals_sorted = sorted(vals)
    median = vals_sorted[len(vals_sorted) // 2]
    p90_position = (len(vals_sorted) - 1) * 0.9
    p90_lower = math.floor(p90_position)
    p90_upper = math.ceil(p90_position)
    p90 = vals_sorted[p90_lower] + (
        vals_sorted[p90_upper] - vals_sorted[p90_lower]
    ) * (p90_position - p90_lower)
    maxv = vals_sorted[-1]
    draw_pill(svg, 46, 294, f"median {median:.3f}x", GREEN, 110)
    draw_pill(svg, 166, 294, f"p90 {p90:.3f}x", BLUE, 100)
    draw_pill(svg, 276, 294, f"max {maxv:.3f}x", ORANGE, 100)
    svg.text(
        46,
        344,
        "Counts include NativePG-RLS, fixed enforcement modes, IndexPriority, and AdmissionFirst.",
        size=10,
        fill=MUTED,
    )
    write_svg_pdf(
        "fig4_e3_speedup",
        svg,
        output_stem=None,
    )


def fig4_e3_speedup_legacy_compact() -> None:
    """Refresh the retained 560x260 compact asset with canonical labels."""

    rows = [r for r in read_rows("fig4_e3_speedup") if r["status"] == "pass"]
    by_cell: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_cell[(row["query_id"], row["policy_config_id"])].append(row)

    points: list[tuple[str, str, float, str]] = []
    winners: Counter[str] = Counter()
    for (query, policy), group in by_cell.items():
        valid = [
            row
            for row in group
            if fnum(row["total_ms_median"], 0)
            and fnum(row["total_ms_median"], 0) > 0
        ]
        if not valid:
            continue
        best = min(
            valid,
            key=lambda row: (
                fnum(row["total_ms_median"], math.inf) or math.inf,
                mode_execution_order_key(row["mode"]),
            ),
        )
        admission_first = next((row for row in valid if row["mode"] == ADMISSION_FIRST_MODE), None)
        if admission_first is None:
            continue
        ratio = (fnum(admission_first["total_ms_median"], 0) or 0) / (
            fnum(best["total_ms_median"], 1) or 1
        )
        winners[best["mode"]] += 1
        points.append((query, policy, ratio, best["mode"]))
    points.sort(key=lambda item: (item[2], item[0], item[1]))

    svg = Svg(560, 260)
    x0, y0, w, h = 46, 48, 300, 160
    svg.text(46, 30, "AF / fastest policy-enforcement mode", size=11, weight="700", fill=MUTED)
    for tick in (1.00, 1.02, 1.04, 1.06):
        x = x0 + (tick - 1.0) / 0.06 * w
        svg.line(x, y0, x, y0 + h, stroke="#e6ebf2")
        svg.text(
            x,
            y0 + h + 17,
            "≥1.06" if math.isclose(tick, 1.06) else f"{tick:.2f}",
            size=9,
            fill=MUTED,
            anchor="middle",
        )
    svg.line(x0, y0 + h, x0 + w, y0 + h, stroke=GRID)
    for index, (_query, policy, ratio, winner_mode) in enumerate(points):
        x = x0 + min(max((ratio - 1.0) / 0.06, 0.0), 1.0) * w
        y = y0 + 8 + (index % 11) * 12 + (
            0
            if policy == "cheap_tenant_sargable"
            else (3 if policy == "group_acl_expensive" else 6)
        )
        svg.circle(x, y, 3, fill=family_color(family_label(winner_mode, experiment="E3")))

    svg.text(360, 30, "Count by fastest family", size=11, weight="700", fill=MUTED)
    ordered_winners = sorted(
        winners.items(), key=lambda item: (-item[1], mode_execution_order_key(item[0]))
    )
    max_count = max(winners.values() or [1])
    for index, (mode, count) in enumerate(ordered_winners):
        label = family_label(mode, experiment="E3")
        y = 42 + index * 34
        svg.text(360, y + 14, label, size=9.5)
        bar = 52 * count / max_count
        svg.rect(488, y + 2, bar, 16, fill=family_color(label), rx=3)
        svg.text(492 + bar, y + 15, str(count), size=10, fill=MUTED)
    write_svg_pdf(
        "fig4_e3_speedup",
        svg,
        output_stem="fig4_e3_speedup_compact",
    )


def fig9_template_oracle_audit() -> None:
    rows = read_rows("fig9_template_oracle_audit")
    summaries = {r["experiment"]: r for r in rows if r["row_type"] == "summary"}
    gaps = sorted(
        fnum(r.get("oracle_gap_median"), None)
        for r in rows
        if r["row_type"] == "cdf_point" and fnum(r.get("oracle_gap_median"), None) is not None
    )
    worst = sorted(
        [r for r in rows if r["row_type"] == "worst_miss"],
        key=lambda r: int(fnum(r.get("worst_rank"), 999) or 999),
    )[:5]
    combined = summaries["combined"]

    svg = Svg(780, 500)
    svg.text(24, 34, "Measured finite-template oracle audit", size=18, weight="700")
    svg.text(24, 55, "Chosen plans are compared with the measured best admitted template in each case.", size=12, fill=MUTED)

    # Top-k and near-best badges.
    svg.text(26, 91, "Rank / near-best coverage", size=11, weight="700", fill=MUTED)
    metrics = [
        ("top-1", "top1_measured_rank_count", GREEN),
        ("top-2", "top2_measured_rank_count", BLUE),
        ("top-3", "top3_measured_rank_count", PURPLE),
        ("within 3%", "near_best_3pct_count", ORANGE),
        ("within 5%", "near_best_5pct_count", GRAY),
    ]
    total = int(fnum(combined["oracle_cell_count"], 1) or 1)
    x0, y0 = 26, 114
    for i, (label, key, color) in enumerate(metrics):
        count = int(fnum(combined[key], 0) or 0)
        y = y0 + i * 31
        svg.text(x0, y + 15, label, size=10)
        svg.rect(x0 + 78, y, 150, 17, fill="#edf2f7", rx=4)
        svg.rect(x0 + 78, y, 150 * count / total, 17, fill=color, rx=4)
        svg.text(x0 + 238, y + 14, f"{count}/{total}", size=10, weight="700", fill=INK)

    # ECDF.
    gx, gy, gw, gh = 332, 96, 390, 180
    svg.text(gx, 91, "Gap ECDF (chosen / measured best)", size=11, weight="700", fill=MUTED)
    for tick in [1.00, 1.03, 1.06, 1.09]:
        x = gx + (tick - 1.0) / 0.09 * gw
        svg.line(x, gy, x, gy + gh, stroke="#e6ebf2")
        tick_label = "≥1.09" if math.isclose(tick, 1.09) else f"{tick:.2f}"
        svg.text(x, gy + gh + 17, tick_label, size=9, fill=MUTED, anchor="middle")
    for tick in [0.0, 0.5, 1.0]:
        y = gy + gh - tick * gh
        svg.line(gx, y, gx + gw, y, stroke="#eef2f7")
        svg.text(gx - 8, y + 4, f"{tick:.1f}", size=9, fill=MUTED, anchor="end")
    points = [(gx, gy + gh)]
    for index, gap in enumerate(gaps, start=1):
        if gap is None:
            continue
        frac = index / max(len(gaps), 1)
        x = gx + min(max((gap - 1.0) / 0.09, 0), 1) * gw
        y = gy + gh - frac * gh
        points.append((x, points[-1][1]))
        points.append((x, y))
    if len(points) > 1:
        points.append((gx + gw, points[-1][1]))
    if points:
        svg.polyline(points, stroke=BLUE, sw=2.4)
        for x, y in points[2:: max(2, len(points) // 12)]:
            svg.circle(x, y, 2.4, fill=BLUE)
    median = fnum(combined.get("median_oracle_gap"), 0) or 0
    p90 = fnum(combined.get("p90_oracle_gap"), 0) or 0
    maxv = fnum(combined.get("max_oracle_gap"), 0) or 0
    below_count = int(fnum(combined.get("below_resolution_cell_count"), 0) or 0)
    bounded_count = int(fnum(combined.get("bounded_cell_count"), 0) or 0)
    bounded_max = fnum(combined.get("bounded_max_oracle_gap"), None)
    floor_ms = fnum(combined.get("measurement_resolution_floor_ms"), 1.0) or 1.0
    max_note = " (max from a below-resolution case)" if bounded_max is not None and maxv > bounded_max else ""
    clipped_count = sum(1 for gap in gaps if gap is not None and gap >= 1.09)
    svg.text(
        gx,
        gy + gh + 36,
        f"median/p90/max = {median:.3f} / {p90:.3f} / {maxv:.3f}{max_note}",
        size=10,
        fill=MUTED,
    )
    if bounded_max is not None:
        svg.text(
            gx,
            gy + gh + 52,
            f"bounded cases (best ≥ {floor_ms:g} ms): {bounded_count}/{total}, max gap {bounded_max:.3f}; "
            f"below-resolution: {below_count}/{total}",
            size=10,
            fill=MUTED,
        )
    if clipped_count:
        svg.text(
            gx + gw,
            gy - 8,
            f"{clipped_count} value(s) at or beyond right edge",
            size=8.5,
            fill=MUTED,
            anchor="end",
        )

    # Worst miss table.
    ty = 344
    svg.text(26, ty, "Worst measured misses", size=11, weight="700", fill=MUTED)
    headers = ["case", "gap", "chosen", "measured best"]
    xs = [26, 300, 360, 532]
    for x, htxt in zip(xs, headers):
        svg.text(x, ty + 24, htxt, size=9, weight="700", fill=MUTED)
    svg.line(26, ty + 31, 742, ty + 31, stroke=GRID)
    any_below_marker = False
    for i, row in enumerate(worst):
        y = ty + 49 + i * 19
        query = str(row.get("query_id", ""))
        query = query.replace("E10_Q1_support_ticket_lookup", "Q1")
        query = query.replace("E10_Q5_invoice_region_purpose_join", "Q5")
        policy = str(row.get("policy_id", "")).replace("hybrid_selective_key", "hybrid key")
        policy = policy.replace("tenant_isolation_break_glass", "break-glass")
        policy = policy.replace("purpose_region_join", "purpose-region")
        policy = policy.replace("cheap_tenant_sargable", "cheap tenant")
        cell = f"{row.get('experiment')} {query}/{policy}"
        below = str(row.get("below_measurement_resolution", "")).lower() == "true"
        marker = "†" if below else ""
        any_below_marker = any_below_marker or below
        svg.text(xs[0], y, cell[:52], size=8.5)
        svg.text(xs[1], y, f"{fnum(row.get('oracle_gap_median'), 0):.3f}{marker}", size=8.5)
        svg.text(xs[2], y, family_label(row.get("chosen_template_id", ""))[:22], size=8.5)
        svg.text(xs[3], y, family_label(row.get("best_template_id", ""))[:22], size=8.5)
    if any_below_marker:
        svg.text(
            26,
            ty + 49 + len(worst) * 19 + 6,
            f"† best execution < {floor_ms:g} ms (below measurement resolution); "
            "gap ratio is sensitive to the sub-millisecond denominator.",
            size=8.5,
            fill=MUTED,
        )
    write_svg_pdf("fig9_template_oracle_audit", svg)


def render_admission_panel() -> Path:
    """Historical separate panel; active manuscript uses the combined renderer."""

    output = Path("figures/plan-admission/admission-panel.pdf")
    subprocess.run(
        [sys.executable, "figures/plan-admission/render_panel.py",
         "--source", "results/figures/fig2_contract_matrix/fig2_contract_matrix_source.csv",
         "--raw-root", "results/raw", "--output", output.as_posix()],
        cwd=ROOT, check=True,
    )
    return ROOT / output


def render_template_pair_panel() -> Path:
    """Historical separate panel; active manuscript uses the combined renderer."""

    output = Path("figures/e4-template-pairs/paired-template-panel.pdf")
    subprocess.run(
        [sys.executable, "figures/e4-template-pairs/render_panel.py",
         "--source", "results/figures/fig6_e4_local_greedy/fig6_e4_local_greedy_source.csv",
         "--output", output.as_posix()],
        cwd=ROOT, check=True,
    )
    return ROOT / output


def render_evaluation_composite() -> Path:
    """Render the four retained evaluation panels as one manuscript figure."""

    output = Path("figures/evaluation-composite/evaluation-panels.pdf")
    subprocess.run(
        [sys.executable, "figures/evaluation-composite/render_panel.py",
         "--output", output.as_posix()],
        cwd=ROOT, check=True,
    )
    return ROOT / output


def render_taxonomy_figures() -> tuple[Path, ...]:
    """Regenerate active label-bearing assets without rewriting retained data."""

    from .reporting import rerender_retained_figure_pdf

    outputs = [render_evaluation_composite()]
    retained = (
        "fig5_e5_template_regret",
        "fig8_e9_overhead",
        "tab2_e10_diversity",
        "tab2_e10_diversity_full_seed42",
    )
    outputs.extend(rerender_retained_figure_pdf(name, FIG_ROOT) for name in retained)
    return tuple(outputs)


def main(argv: Iterable[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--taxonomy",
        action="store_true",
        help="regenerate only active AdmissionFirst/policy-enforcement label-bearing assets",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.taxonomy:
        render_taxonomy_figures()
        return
    render_evaluation_composite()
    fig3_e2_phase_diagram()
    fig3_e2_phase_diagram(compact=True)
    fig3_e2_phase_diagram_legacy_compact()
    fig9_template_oracle_audit()


if __name__ == "__main__":
    main()
