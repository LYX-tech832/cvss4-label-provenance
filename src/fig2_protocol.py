"""图 2：来源感知评测协议示意图（纯作图，数字来自已核实的结果：第 4.1 节表 3、第 5.2 节表 5）。

四步：1 数据 → 2 来源分型（只用 2026 年以前的数据）→ 3 划分（时间划分 + 留一来源）→ 4 报告（按标签类型；指标；选模型与统计）。
颜色与图 1 一致：derived = VulDB 的橙色，independent = VulnCheck 的蓝色。
输出：paper/figures/fig2_protocol.pdf、.png
"""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Rectangle  # noqa: E402

OUT = Path(__file__).resolve().parents[1] / "paper" / "figures"
C = {"derived": "#D55E00", "independent": "#0072B2", "v4only": "#009E73", "other": "#9E9E9E",
     "box": "#F4F4F4", "edge": "#555555", "train": "#CFE3F1", "val": "#8DB8D8", "test": "#3E7CB1", "line": "#333333"}


def box(ax, x, y, w, h, text=None, fc=C["box"], ec=C["edge"], fs=7, tc="black"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.25,rounding_size=0.8", fc=fc, ec=ec, lw=0.7))
    if text:
        ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, color=tc, linespacing=1.25)


def titled_box(ax, x, y, w, h, title, body, fs=6.5):
    """标题加粗、正文左对齐的方框。"""
    box(ax, x, y, w, h)
    ax.text(x + w / 2, y + h - 2.0, title, ha="center", va="center", fontsize=7.2, fontweight="bold")
    ax.text(x + 1.0, y + h - 4.2, body, ha="left", va="top", fontsize=fs, linespacing=1.3)


def arrow(ax, p, q, rad=0.0):
    ax.add_patch(FancyArrowPatch(p, q, arrowstyle="-|>", mutation_scale=9, lw=0.9, color=C["line"],
                                 connectionstyle=f"arc3,rad={rad}", shrinkA=1, shrinkB=1))


def main():
    plt.rcParams.update({"font.family": "Arial"})
    fig = plt.figure(figsize=(7.2, 3.55))
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 50)
    ax.axis("off")

    for x, t in [(12.5, "1. Data"), (36, "2. Provenance typing"), (63, "3. Splits"), (89, "4. Reporting")]:
        ax.text(x, 47.6, t, ha="center", va="center", fontsize=8.5, fontweight="bold")

    # 1 数据（左侧留出走线的空间）
    box(ax, 4.0, 34.5, 17, 9.5, "CVE List snapshot\n(25 Sep 2026)\n379,060 published\nrecords")
    box(ax, 4.0, 19.0, 17, 11.5, "v4.0 dataset\n37,997 CNA-provided\nv4.0 labels, 300 CNAs\n(23,473 dual-scored)")
    box(ax, 4.0, 3.0, 17, 12.0, "v3.1 pool\n110,524 CVEs with v3.1\nbut no v4.0\n(published before 2026)\nauxiliary training only", fs=6.8)
    arrow(ax, (12.5, 34.2), (12.5, 31.0))
    ax.plot([3.7, 1.6, 1.6], [39.2, 39.2, 9.0], color=C["line"], lw=0.9)  # 快照 → v3.1 池：从左侧绕行
    arrow(ax, (1.6, 9.0), (3.7, 9.0))

    # 2 来源分型
    box(ax, 25.0, 34.5, 22, 9.5, "Dual-scored CNAs: out-of-sample\nfunctional dependence FD$_{oos}$\nof v4.0 on the CNA's own v3.1\n(data before 2026 only)")
    types = [("derived", "derived: FD$_{oos}$ ≥ 0.90\n(VulDB)"),
             ("independent", "independent: FD$_{oos}$ < 0.90\n(VulnCheck, siemens, …)"),
             ("v4only", "v4-only: < 5% dual-scored\n(GitHub, INCIBE, …)"),
             ("other", "other: too few CVEs to test")]
    for i, (k, t) in enumerate(types):
        box(ax, 25.0, 25.2 - i * 7.2, 22, 5.6, t, fc=C[k], ec=C[k], fs=6.8, tc="white")
    arrow(ax, (21.3, 24.7), (24.6, 39.0), rad=-0.25)
    arrow(ax, (36, 34.2), (36, 31.3))

    # 3 划分：从分型列中点同时指向两种划分
    box(ax, 51.5, 26.0, 23, 18.0)
    ax.text(63, 41.8, "Temporal split", ha="center", va="center", fontsize=7.2, fontweight="bold")
    bx, by, bw, bh = 53.0, 32.6, 20.0, 4.2
    for k, a, b, t in [("train", 0.00, 0.60, "train\n< 2026"), ("val", 0.60, 0.73, "val"), ("test", 0.73, 1.00, "test\n2026")]:
        ax.add_patch(Rectangle((bx + a * bw, by), (b - a) * bw, bh, fc=C[k], ec="white", lw=0.8))
        ax.text(bx + (a + b) / 2 * bw, by + bh / 2, t, ha="center", va="center", fontsize=6.2,
                color="white" if k == "test" else "black", linespacing=1.0)
    ax.text(63, 29.3, "train 14,488 · val 1,609 (latest 10%)\ntest 21,900 (1 Jan – 24 Sep 2026)", ha="center",
            va="center", fontsize=6.3, linespacing=1.25)
    box(ax, 51.5, 3.0, 23, 19.5)
    ax.text(63, 20.3, "Leave-one-source-out", ha="center", va="center", fontsize=7.2, fontweight="bold")
    ax.text(63, 17.6, "train on all other CNAs", ha="center", va="center", fontsize=6.3, style="italic")
    for i, (k, t) in enumerate([("independent", "hold out VulnCheck  (test 7,429)"),
                                ("v4only", "hold out GitHub  (test 5,129)"),
                                ("derived", "hold out VulDB  (test 12,882)")]):
        y = 13.4 - i * 4.3
        ax.add_patch(Rectangle((53.0, y - 1.1), 2.2, 2.2, fc=C[k], ec="none"))
        ax.text(56.2, y, t, ha="left", va="center", fontsize=6.6)
    ax.plot([47.6, 48.1, 48.1, 47.6], [31.0, 31.0, 3.4, 3.4], color=C["line"], lw=0.9)  # 右侧括号：四类标签都进入两种划分
    ax.plot([48.1, 49.3], [17.4, 17.4], color=C["line"], lw=0.9)
    arrow(ax, (49.3, 17.4), (51.2, 33.0), rad=-0.2)
    arrow(ax, (49.3, 17.4), (51.2, 12.0), rad=0.2)

    # 4 报告
    titled_box(ax, 78.5, 26.0, 20.5, 18.0, "Report per label type",
               "• headline: non-derived labels\n• derived: reported separately\n• LOSO–VulDB: reproduction\n   of a derived source")
    titled_box(ax, 78.5, 3.0, 20.5, 19.5, "Metrics and statistics",
               "• vector: mean macro-F1,\n   v4-specific F1, exact match\n• decision: CVSS-B MAE, band\n   accuracy, under-estimation,\n"
               "   High+Critical recall\n• selection on validation only\n• 5 seeds; paired bootstrap\n   within each split", fs=6.3)
    arrow(ax, (74.8, 35.0), (78.2, 35.0))
    arrow(ax, (74.8, 12.8), (78.2, 12.8))

    OUT.mkdir(parents=True, exist_ok=True)
    for ext in ("pdf", "png"):
        fig.savefig(OUT / f"fig2_protocol.{ext}", dpi=300)


if __name__ == "__main__":
    main()
