#!/usr/bin/env python3
"""Draw the paper's three latency figures from results/conditions.csv.

    python3 results/figures.py [--output DIR]

Writes fig-overall-latency-cdf, fig-original-queries and fig-search as PDF
and PNG (default directory: results/figures). Requires matplotlib and numpy.
The paper uses the Linux Libertine font; set AF_FIGURE_FONT to its .ttf file
to use it, otherwise STIX is used. The data points do not depend on the font.
"""

import argparse
import csv
import json
import math
import os
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from matplotlib import font_manager, ticker  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402

HERE = Path(__file__).resolve().parent
WORKLOAD = HERE.parent / "workload"
METHODS = ("native", "index_priority", "in_rewrite", "af")
BASELINES = METHODS[:-1]
STYLE = {
    "native": dict(label="Native RLS", color="#525862", linestyle=":", marker="v"),
    "index_priority": dict(label="IndexPriority", color="#A54A19", linestyle="--", marker="s"),
    "in_rewrite": dict(label="IN rewrite", color="#285F9E", linestyle="-.", marker="D"),
    "af": dict(label="AF", color="#087454", linestyle="-", marker="o"),
}
ORIGINAL_QUERIES = (
    ("(a) TPC-H SF1", ["tpch-q3", "tpch-q5", "tpch-q7", "tpch-q10"], ["Q3", "Q5", "Q7", "Q10"]),
    ("(b) JOB", ["job-1a", "job-2a", "job-3c", "job-6d", "job-10a", "job-16b", "job-31a"],
     ["1a", "2a", "3c", "6d", "10a", "16b", "31a"]),
)
SEARCH_GROUPS = (("independent-sparse", "(a) 1% readable"),
                 ("independent-dense", "(b) 80% readable"),
                 ("concentrated-sparse", "(c) 1%, one directory"))
PREFIXES = (("prefix-0.1pct", "0.1"), ("prefix-1pct", "1"), ("prefix-20pct", "20"), ("no-prefix", "none"))


def setup_fonts(size=8):
    font = "STIXGeneral"
    path = os.environ.get("AF_FIGURE_FONT")
    if path and Path(path).is_file():
        font_manager.fontManager.addfont(path)
        font = font_manager.FontProperties(fname=path).get_name()
    plt.rcParams.update({
        "font.family": font, "font.size": size, "pdf.fonttype": 42,
        "axes.labelpad": 2.5, "axes.linewidth": .55,
        "xtick.major.size": 2.2, "ytick.major.size": 2.2,
        "xtick.major.width": .55, "ytick.major.width": .55,
        "xtick.major.pad": 2, "ytick.major.pad": 2,
        "legend.fontsize": 7.8, "legend.frameon": False,
        "legend.columnspacing": 1.15, "legend.handlelength": 2,
        "legend.handletextpad": .45, "hatch.linewidth": .4,
        "savefig.facecolor": "white",
    })


def load(path):
    with path.open(newline="", encoding="utf-8") as stream:
        return {row["case"]: row for row in csv.DictReader(stream)}


def latency(row, method):
    value = float(row[method + "_ms"])
    assert math.isfinite(value) and value > 0
    return value


def measured(row, method):
    return row[method + "_ms"] != ""


def af_path(case):
    """The 'AF Path' of the first AF operator in the recorded plan of a case."""
    plan = json.loads((WORKLOAD / "cases" / case / "expected-plan.json").read_text(encoding="utf-8"))
    stack = [plan]
    while stack:
        node = stack.pop(0)
        if isinstance(node, dict):
            if "AF Path" in node:
                return node["AF Path"]
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return None


def save(fig, output, stem):
    fig.savefig(output / (stem + ".pdf"), metadata={"CreationDate": None, "ModDate": None})
    fig.savefig(output / (stem + ".png"), dpi=220)
    plt.close(fig)


def search_figure(rows, output):
    """Document-path searches over one million documents; labels name AF's access method."""
    setup_fonts(7)
    width, height = 3.32, 1.58
    fig = plt.figure(figsize=(width, height))
    left, right, gap, bottom, top = .36, .04, .10, .43, .20
    weights = (4.8, 4.8, 3.8)
    usable = width - left - right - 2 * gap
    x0 = left
    for i, ((group, title), weight) in enumerate(zip(SEARCH_GROUPS, weights)):
        w = usable * weight / sum(weights)
        ax = fig.add_axes([x0 / width, bottom / height, w / width, (height - bottom - top) / height])
        keys = [(p, label) for p, label in PREFIXES if f"path-search/{group}-{p}" in rows]
        cases = [rows[f"path-search/{group}-{p}"] for p, _ in keys]
        for method in METHODS:
            ax.plot(range(len(keys)), [latency(row, method) for row in cases],
                    lw=1 if method == "af" else .85, markersize=2.9,
                    markerfacecolor=STYLE[method]["color"] if method == "af" else "white",
                    markeredgewidth=.6, zorder=4 if method == "af" else 3, **STYLE[method])
        ax.set(yscale="log", ylim=(2.2, 5000), xlim=(-.4, len(keys) - .6))
        ax.set_xticks(range(len(keys)), [label for _, label in keys])
        ax.set_yticks([10, 100, 1000], ["10", "100", "1000"])
        ax.yaxis.set_minor_locator(ticker.LogLocator(subs=np.arange(2, 10)))
        ax.yaxis.set_minor_formatter(ticker.NullFormatter())
        ax.tick_params(labelsize=7)
        ax.grid(axis="y", color=".86", linewidth=.35)
        ax.set_axisbelow(True)
        if i:
            ax.tick_params(labelleft=False)
        else:
            ax.set_ylabel("Latency (ms)", fontsize=7, labelpad=1.4)
        # The labels name the access method in AF's recorded plans.
        if i == 0:
            assert af_path("path-search/independent-sparse-prefix-0.1pct") == "prefix_pending_index"
            assert af_path("path-search/independent-sparse-prefix-1pct") == "enumerate_authorized_keys"
            ax.text(.25, 2.7, "guard", color="#064a37", fontsize=6.8, ha="center")
            ax.text(2.1, 7.3, "keys first", color="#064a37", fontsize=6.8, ha="center")
        elif i == 1:
            assert af_path("path-search/independent-dense-prefix-1pct") == "prefix_pending_seq"
            assert af_path("path-search/independent-dense-prefix-20pct") == "completed_hash_policy"
            ax.text(.45, 5.4, "guard", color="#064a37", fontsize=6.8, ha="center")
            ax.text(1.95, 150, "hash check", color="#064a37", fontsize=6.8, ha="center")
        else:
            ax.text(.10, 3.7, "guard", color="#064a37", fontsize=6.8, ha="center")
            ax.text(1.3, 9, "keys first", color="#064a37", fontsize=6.8, ha="center")
        fig.text((x0 + w / 2) / width, .025 / height, title, fontsize=7, ha="center", va="bottom")
        x0 += w + gap
    fig.text((left + width - right) / 2 / width, .16 / height, "Prefix range (% of documents)",
             fontsize=7, ha="center")
    handles = [Line2D([], [], color=STYLE[m]["color"], linestyle=STYLE[m]["linestyle"],
                      marker=STYLE[m]["marker"], lw=.9, markersize=2.9,
                      markerfacecolor=STYLE[m]["color"] if m == "af" else "white",
                      markeredgewidth=.6) for m in METHODS]
    fig.legend(handles, [STYLE[m]["label"] for m in METHODS], loc="upper center", ncol=4,
               bbox_to_anchor=(.52, 1.0), borderaxespad=.1, handlelength=1.2,
               fontsize=6.7, columnspacing=.75, handletextpad=.3)
    save(fig, output, "fig-search")


def overall_figure(rows, output):
    """Distribution of baseline latency / AF latency over all measured cases."""
    setup_fonts()
    fig, axes = plt.subplots(1, 2, figsize=(7, 1.5), sharey=True)
    fig.subplots_adjust(left=.073, right=.955, bottom=.26, top=.75, wspace=.15)
    for ax, family, title in zip(axes, ("benchmark", "application"),
                                 ("TPC-H and JOB", "Multi-tenant application")):
        workload = [r for r in rows.values() if r["family"] == family]
        ax.set_title(title, fontsize=8, pad=2)
        ax.set(xscale="log", xlim=(.03, 1000), ylim=(0, 105))
        ax.set_xticks([.1, 1, 10, 100, 1000], ["0.1×", "1×", "10×", "100×", "1,000×"])
        ax.xaxis.set_minor_locator(ticker.NullLocator())
        ax.set_yticks([0, 50, 100])
        ax.spines[["right", "top"]].set_visible(False)
        ax.grid(axis="y", color="#E2E5E7", lw=.55)
        ax.set_axisbelow(True)
        ax.axvline(1, color="#777C83", lw=.6, linestyle=(0, (2, 2)))
        handles = []
        for method in BASELINES:
            usable = [r for r in workload if measured(r, method)]
            ratios = sorted(latency(r, method) / latency(r, "af") for r in usable)
            line, = ax.step([.03, *ratios, 1000],
                            [0, *(100 * k / len(ratios) for k in range(1, len(ratios) + 1)), 100],
                            where="post", lw=1, markersize=2.2, markeredgewidth=.55,
                            markerfacecolor="white", markevery=[round(q * len(ratios)) for q in (.23, .54, .81)],
                            **STYLE[method])
            handles.append(line)
    axes[0].set_ylabel("Cumulative cases (%)")
    fig.supxlabel("Baseline latency / AF latency (log scale)", fontsize=8, y=.035)
    fig.legend(handles=handles, loc="upper center", bbox_to_anchor=(.5, 1), ncols=3)
    save(fig, output, "fig-overall-latency-cdf")


def original_figure(rows, output):
    """Median latency of original TPC-H and JOB queries under a membership policy."""
    setup_fonts()
    fig, axes = plt.subplots(1, 2, figsize=(7, 2.05), sharey=True, gridspec_kw={"width_ratios": [4, 7.4]})
    fig.subplots_adjust(left=.105, right=.986, top=.82, bottom=.25, wspace=.12)
    for ax, (title, queries, labels) in zip(axes, ORIGINAL_QUERIES):
        positions = list(range(len(queries)))
        if title.endswith("JOB"):
            positions[-1] += .48
        selected = [rows[f"original/{q}-membership"] for q in queries]
        for i, (method, hatch) in enumerate(zip(METHODS, ("", "///", "..", ""))):
            color = STYLE[method]["color"]
            fill = dict(native="#d3d6d9", index_priority="#f4ddce", in_rewrite="#d9e7f6", af=color)[method]
            ax.bar([x + (i - 1.5) * .19 for x in positions],
                   [latency(r, method) - 1 for r in selected], bottom=1, width=.168,
                   color=fill, edgecolor=color, hatch=hatch, lw=.55, label=STYLE[method]["label"])
        ax.set(yscale="log", ylim=(1, 100000), xticks=positions, xticklabels=labels,
               xlim=(-.52, positions[-1] + .52))
        ax.yaxis.set_minor_locator(ticker.NullLocator())
        ax.yaxis.set_major_locator(ticker.FixedLocator([1, 10, 100, 1000, 10000, 100000]))
        ax.yaxis.set_major_formatter(ticker.StrMethodFormatter("{x:,.0f}"))
        ax.grid(axis="y", color="#dee2e6", lw=.55)
        ax.set_axisbelow(True)
        ax.spines[["right", "top"]].set_visible(False)
        if title.endswith("JOB"):
            ax.axvline((positions[-2] + positions[-1]) / 2, color="#9b9fa3", linestyle=(0, (2, 3)), lw=.75)
            ax.tick_params(axis="y", left=False)
            ax.text(positions[-1], 80000, "join reduction", ha="center", va="top", fontsize=7.2)
        ax.text(.5, -.34, title, transform=ax.transAxes, ha="center", va="top", fontsize=9)
    axes[0].set_ylabel("Median request latency (ms)", fontsize=9)
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(.54, .985), ncols=4, fontsize=9)
    save(fig, output, "fig-original-queries")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--conditions", type=Path, default=HERE / "conditions.csv")
    parser.add_argument("--output", type=Path, default=HERE / "figures")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    rows = load(args.conditions)
    overall_figure(rows, args.output)
    original_figure(rows, args.output)
    search_figure(rows, args.output)
    print("figures written to", args.output)


if __name__ == "__main__":
    main()
