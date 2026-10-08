"""图 2：来源感知评测协议示意图（纯作图，数字来自已核实的结果：第 4.1 节表 3、第 5.2 节表 5）。

四步：1 数据 → 2 来源分型（只用 2026 年以前的数据）→ 3 划分（时间划分 + 留一来源）→ 4 报告（按标签类型；指标；选模型与统计）。
颜色与图 1 一致：derived = VulDB 的橙色，undetected（未检出达到阈值的依赖）= VulnCheck 的蓝色。
10-02 第二轮审稿（N5）：原图按 7.2 英寸画、排版时缩到正文宽度 5.4 英寸，字只有约 5 pt；
改为按正文宽度 1:1 作图的 2×2 布局（字号 7–9 pt），样本池在图内分别写明时间划分与留一来源的口径。
输出：paper/figures/fig2_protocol.pdf、.png，并同步到 paper/latex/figures/（LaTeX 编译实际用这一份）。
"""

import shutil
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Rectangle  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "paper" / "figures"
LATEX_FIG = ROOT / "paper" / "latex" / "figures"
C = {"derived": "#D55E00", "undetected": "#0072B2", "v4only": "#009E73", "other": "#8A8A8A",
     "box": "#F4F4F4", "edge": "#555555", "train": "#CFE3F1", "val": "#8DB8D8", "test": "#3E7CB1", "line": "#333333"}
W_IN = 5.4  # 正文宽度（elsarticle preprint 12pt，实测 388.5 pt）
FS, FS_SMALL, FS_TITLE, FS_HEAD = 7.6, 7.2, 8.2, 9.2


def box(ax, x, y, w, h, text=None, fc=C["box"], ec=C["edge"], fs=FS, tc="black"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.3,rounding_size=0.9", fc=fc, ec=ec, lw=0.7))
    if text:
        ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, color=tc, linespacing=1.25)


def titled_box(ax, x, y, w, h, title, body, fs=FS_SMALL):
    box(ax, x, y, w, h)
    ax.text(x + w / 2, y + h - 2.3, title, ha="center", va="center", fontsize=FS_TITLE, fontweight="bold")
    ax.text(x + 1.4, y + h - 4.8, body, ha="left", va="top", fontsize=fs, linespacing=1.3)


def arrow(ax, p, q, rad=0.0):
    ax.add_patch(FancyArrowPatch(p, q, arrowstyle="-|>", mutation_scale=9, lw=0.9, color=C["line"],
                                 connectionstyle=f"arc3,rad={rad}", shrinkA=1, shrinkB=1))


def main():
    plt.rcParams.update({"font.family": "Arial"})
    ymax = 96
    fig = plt.figure(figsize=(W_IN, W_IN * ymax / 100))
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 100)
    ax.set_ylim(0, ymax)
    ax.axis("off")

    for x, y, t in [(24, 93.6, "1. Data"), (76, 93.6, "2. Provenance typing"), (24, 45.6, "3. Splits"), (76, 45.6, "4. Reporting")]:
        ax.text(x, y, t, ha="center", va="center", fontsize=FS_HEAD, fontweight="bold")

    # 1 数据：快照在上；左为 v3.1 样本池（只用于辅助训练，向下进入划分），右为 v4.0 数据集（进入来源分型）
    box(ax, 2, 81.5, 44, 8, "CVE List snapshot (25 Sep 2026)\n379,060 published records")
    box(ax, 2, 50.5, 21, 26.5, "v3.1 pool\n(v3.1 but no v4.0)\n\ntemporal: 110,524\nCVEs published\nbefore 2026\n\nLOSO: all dates,\nheld-out CNA\nremoved", fs=FS_SMALL)
    box(ax, 25, 50.5, 21, 26.5, "v4.0 dataset\n\n37,997 CNA-provided\nv4.0 labels from\n300 CNAs\n\n23,473 dual-scored", fs=FS_SMALL)
    arrow(ax, (12.5, 81.2), (12.5, 77.4))
    arrow(ax, (35.5, 81.2), (35.5, 77.4))

    # 2 来源分型
    box(ax, 54, 80.5, 44, 9, "Dual-scored CNAs, data before 2026:\nout-of-sample functional dependence\nFD$_{oos}$ of v4.0 on the CNA's own v3.1")
    types = [("derived", "derived: FD$_{oos}$ ≥ 0.90\n(VulDB)"),
             ("undetected", "undetected: FD$_{oos}$ < 0.90\n(VulnCheck, siemens, …)"),
             ("v4only", "v4-only: < 5% dual-scored\n(GitHub, INCIBE, …)"),
             ("other", "other: too few CVEs to test")]
    for i, (k, t) in enumerate(types):
        box(ax, 54, 70.0 - i * 6.6, 44, 5.4, t, fc=C[k], ec=C[k], fs=FS_SMALL, tc="white")
    arrow(ax, (76, 80.2), (76, 75.8))
    arrow(ax, (46.4, 66), (53.6, 84.5), rad=-0.3)

    # 3 划分
    box(ax, 2, 23, 44, 18.5)
    ax.text(24, 39.2, "Temporal split", ha="center", va="center", fontsize=FS_TITLE, fontweight="bold")
    bx, by, bw, bh = 4, 30.6, 40, 5.4
    for k, a, b, t in [("train", 0.00, 0.60, "train: < 2026"), ("val", 0.60, 0.73, "val"), ("test", 0.73, 1.00, "test: 2026")]:
        ax.add_patch(Rectangle((bx + a * bw, by), (b - a) * bw, bh, fc=C[k], ec="white", lw=0.8))
        ax.text(bx + (a + b) / 2 * bw, by + bh / 2, t, ha="center", va="center", fontsize=FS_SMALL,
                color="white" if k == "test" else "black")
    ax.text(24, 26.4, "train 14,488 · val 1,609 (latest 10%)\ntest 21,900 (1 Jan – 24 Sep 2026)", ha="center",
            va="center", fontsize=FS_SMALL, linespacing=1.25)
    box(ax, 2, 2, 44, 18.5)
    ax.text(24, 18.2, "Leave-one-source-out", ha="center", va="center", fontsize=FS_TITLE, fontweight="bold")
    ax.text(24, 15.2, "train on all other CNAs", ha="center", va="center", fontsize=FS_SMALL, style="italic")
    for i, (k, t) in enumerate([("undetected", "hold out VulnCheck (test 7,429)"),
                                ("v4only", "hold out GitHub (test 5,129)"),
                                ("derived", "hold out VulDB (test 12,882)")]):
        y = 11.4 - i * 3.6
        ax.add_patch(Rectangle((8, y - 1.2), 2.4, 2.4, fc=C[k], ec="none"))
        ax.text(12, y, t, ha="left", va="center", fontsize=FS_SMALL)
    arrow(ax, (12.5, 50.2), (12.5, 42.0))  # 样本池只进入训练
    ax.text(11.4, 46.0, "auxiliary\ntraining\nonly", ha="right", va="center", fontsize=6.8, style="italic", linespacing=1.1)
    arrow(ax, (76, 49.6), (31.5, 45.6))  # 分型 → 划分（按类型报告）

    # 4 报告
    titled_box(ax, 54, 26.5, 44, 15, "Report per source and label type",
               "• derived labels: reported separately\n• source profile: vectors, base rate, κ\n• source-macro averages; NVD reference")
    titled_box(ax, 54, 2, 44, 22.5, "Metrics and statistics",
               "• vector: mean macro-F1, v4-specific F1,\n   exact match\n• decision: CVSS-B MAE, band accuracy,\n   underestimation, High+Critical recall\n"
               "• selection on each split's validation set\n• 5 seeds; paired bootstrap within each split")
    arrow(ax, (46.4, 32), (53.6, 33))
    arrow(ax, (46.4, 11), (53.6, 12))

    OUT.mkdir(parents=True, exist_ok=True)
    for ext in ("pdf", "png"):
        fig.savefig(OUT / f"fig2_protocol.{ext}", dpi=300)
    LATEX_FIG.mkdir(parents=True, exist_ok=True)
    shutil.copy2(OUT / "fig2_protocol.pdf", LATEX_FIG / "fig2_protocol.pdf")


if __name__ == "__main__":
    main()
