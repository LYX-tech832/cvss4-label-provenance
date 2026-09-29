"""图 1：主要 CNA 的 v4.0 向量与"规则 R 换算其自身 v3.1 向量"完全一致的比例，按季度统计（CPU）。

- 只统计同一 CNA 同时给出 v3.1 与 v4.0 的 CVE（双标）；季度按 CVE 发布日期划分；
- 上图：各 CNA 每季度的一致率（样本少于 MIN_N 的季度不画）；下图：每季度双标 v4.0 标签的数量（VulDB / VulnCheck / 其他）；
- 数字直接从原始数据重算（不用 results/label_provenance/summary.md 里四舍五入到整数的汇总）。
输出：paper/figures/fig1_rule_agreement.pdf、.png 和作图数据 fig1_data.csv
"""

import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import M31, M40, load  # noqa: E402
from rq1_stats import rule_convert  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "paper" / "figures"
MIN_N = 30
CNAS = ["VulDB", "VulnCheck", "icscert", "siemens", "intel", "juniper"]
# Okabe–Ito 色板（色盲友好）
COLORS = {"VulDB": "#D55E00", "VulnCheck": "#0072B2", "icscert": "#009E73", "siemens": "#CC79A7",
          "intel": "#E69F00", "juniper": "#56B4E9", "other CNAs": "#BBBBBB"}


def main():
    df = load()
    d = df[df["has_v31"]].copy()
    d["hit"] = [tuple(rule_convert({k: r["x31_" + k] for k in M31})[k] for k in M40) == tuple(r["y_" + k] for k in M40)
                for _, r in d.iterrows()]
    d["q"] = d["pub"].dt.tz_localize(None).dt.to_period("Q")
    g = d.groupby(["source", "q"])["hit"].agg(n="size", hits="sum").reset_index()
    g["rate"] = g["hits"] / g["n"]
    OUT.mkdir(parents=True, exist_ok=True)
    g[g["source"].isin(CNAS)].sort_values(["source", "q"]).to_csv(OUT / "fig1_data.csv", index=False)

    quarters = pd.period_range(pd.Period("2024Q2"), d["q"].max(), freq="Q")  # 2024Q1 全部 CNA 合计只有 21 条双标
    plt.rcParams.update({"font.family": "Arial", "font.size": 8, "axes.linewidth": 0.6})
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(5.5, 4.4), sharex=True, gridspec_kw={"height_ratios": [2.3, 1]})

    for s in CNAS:
        r = g[(g["source"] == s) & (g["n"] >= MIN_N)].set_index("q")["rate"].reindex(quarters)  # 缺失或样本不足的季度为 NaN → 断线
        if r.isna().all():
            continue
        ax1.plot(range(len(quarters)), r.values * 100, marker="o", ms=3.5 if s != "VulDB" else 4.5,
                 lw=1.0 if s != "VulDB" else 1.8, color=COLORS[s], label=s, zorder=3 if s == "VulDB" else 2)
    ax1.set_ylim(0, 105)
    ax1.set_ylabel("Agreement with rule R (%)")
    ax1.grid(axis="y", lw=0.4, alpha=0.5)
    ax1.legend(ncol=6, fontsize=7, frameon=False, loc="lower center", bbox_to_anchor=(0.5, 1.0),
               handlelength=1.6, columnspacing=1.0)

    counts = d[d["q"].isin(quarters)].assign(grp=lambda x: x["source"].where(x["source"].isin(["VulDB", "VulnCheck"]), "other CNAs"))
    c = counts.groupby(["q", "grp"]).size().unstack(fill_value=0).reindex(quarters, fill_value=0)
    bottom = None
    for grp in ["VulDB", "VulnCheck", "other CNAs"]:
        vals = c[grp] if grp in c else 0
        ax2.bar(range(len(quarters)), vals, bottom=bottom, color=COLORS[grp], width=0.7, label=grp)
        bottom = vals if bottom is None else bottom + vals
    ax2.set_ylabel("Dual-scored\nv4.0 labels")
    ax2.legend(ncol=3, fontsize=7, frameon=False, loc="upper left")
    ax2.set_xticks(range(len(quarters)))
    ax2.set_xticklabels([str(q) for q in quarters], rotation=45, ha="right")
    for ax in (ax1, ax2):
        ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    for ext in ("pdf", "png"):
        fig.savefig(OUT / f"fig1_rule_agreement.{ext}", dpi=300)
    print(g[g["source"].isin(CNAS) & (g["n"] >= MIN_N) & g["q"].isin(quarters)].to_string(index=False))
    print("\n每季度双标数量：\n", c.to_string())


if __name__ == "__main__":
    main()
