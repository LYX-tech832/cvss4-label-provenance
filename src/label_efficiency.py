"""W5 标签效率曲线（CPU）：只用 5% / 10% / 25% / 50% 的 v4 训练标签时，"无辅助"与"有 v3.1 辅助"两个版本的表现。

- 100% 的点取 W4 时间划分的选定配置（种子 0–4；曲线上只用种子 0–2，与其余比例的种子数一致，表里另列 5 种子的均值）；
- 指标从 pred_latent.parquet 用 evaluate() 重算：全部测试集与去掉 derived 两种口径；
- 每个比例做各划分内同款的配对 bootstrap（aux − none，先按种子平均，1,000 次重抽样，95% 区间）。
输出：results/label_efficiency/summary.md、data.csv；图 3：paper/figures/fig3_label_efficiency.{pdf,png}
"""

import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import paired_bootstrap  # noqa: E402
from baselines_v0 import evaluate, load, source_type_map  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
OUT = ROOT / "results" / "label_efficiency"
FIG = ROOT / "paper" / "figures"
FRACS = [0.05, 0.1, 0.25, 0.5, 1.0]
N_TRAIN = 14488  # 时间划分的 v4 训练集（不含验证集）
KEYS = ["mean_macro_f1", "band_acc", "under_rate", "score_mae", "exact_match"]


def run_dirs(frac, ver):
    """返回 {种子: 运行目录}。"""
    stem = "T2_temporal_deberta-v3-base_none" + ("_aux_e5" if ver == "aux" else "_e*") + "_cwinv_sqrt"
    pat = stem + (f"_frac{frac:g}_s*" if frac < 1 else "_s*")
    out = {}
    for d in ENC.glob(pat):
        if not (d / "pred_latent.parquet").exists():
            continue
        if frac == 1.0 and ("frac" in d.name or (ver == "none" and "_e5_" not in d.name)):
            continue
        out[int(d.name.rsplit("_s", 1)[1])] = d
    return dict(sorted(out.items()))


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    rows = []
    for frac in FRACS:
        for ver in ["none", "aux"]:
            for seed, d in run_dirs(frac, ver).items():
                p = pd.read_parquet(d / "pred_latent.parquet")
                t = df.set_index("cve_id").loc[p["cve_id"]].reset_index()
                for scope, m in [("all", np.ones(len(t), bool)), ("non_derived", (t["label_type"] != "derived").to_numpy())]:
                    r = evaluate(t[m].reset_index(drop=True), p[m].reset_index(drop=True))
                    rows.append({"frac": frac, "n_labels": round(N_TRAIN * frac), "version": ver, "seed": seed, "scope": scope,
                                 **{k: r[k] for k in KEYS}})
    data = pd.DataFrame(rows)
    OUT.mkdir(parents=True, exist_ok=True)
    data.to_csv(OUT / "data.csv", index=False)

    lines = ["# 标签效率曲线（T2 时间划分，自动生成）\n",
             "- 5%–50%：每个比例 3 个种子（0–2），训练标签按种子随机抽样，验证集、测试集、辅助样本不变；",
             "- 100%：W4 选定配置；表中\"100%（种子 0–2）\"与曲线一致，\"100%（种子 0–4）\"为 W4 主实验的 5 种子均值；",
             "- 无辅助版本的训练轮数按比例放大（5% 与 10%：50 轮；25%：20 轮；50%：10 轮；100%：5 轮），有辅助版本均为 5 轮。\n"]
    for scope, title in [("all", "全部测试集（21,900 条）"), ("non_derived", "去掉 derived（16,749 条）")]:
        lines += [f"\n## {title}：均值 ± 标准差\n", "| v4 训练标签 | 版本 | 种子数 | " + " | ".join(KEYS) + " |", "|---|---|---|" + "---|" * len(KEYS)]
        for frac in FRACS:
            for ver in ["none", "aux"]:
                sets = [("", data[(data.frac == frac) & (data.version == ver) & (data.scope == scope) & (data.seed <= 2)])]
                if frac == 1.0:
                    sets.append(("（种子 0–4）", data[(data.frac == frac) & (data.version == ver) & (data.scope == scope)]))
                for tag, g in sets:
                    if g.empty:
                        continue
                    lab = f"{frac:.0%}（{round(N_TRAIN * frac):,} 条）{tag}"
                    lines.append(f"| {lab} | {'有辅助' if ver == 'aux' else '无辅助'} | {len(g)} | "
                                 + " | ".join(f"{g[k].mean():.3f} ± {g[k].std(ddof=1):.3f}" for k in KEYS) + " |")

    lines += ["\n## 各比例的配对 bootstrap（有辅助 − 无辅助；种子 0–2 先平均；1,000 次；95% 区间）\n",
              "| v4 训练标签 | 口径 | 平均宏 F1 差 | 等级准确率差 | 低估率差 | 分数 MAE 差 |", "|---|---|---|---|---|---|"]
    for frac in FRACS:
        none = {s: d for s, d in run_dirs(frac, "none").items() if s <= 2}
        aux = {s: d for s, d in run_dirs(frac, "aux").items() if s <= 2}
        if not none or not aux:
            continue
        res = paired_bootstrap(df, none, aux, B=1000)
        for scope, r in res.items():
            cells = " | ".join(f"{r[k][0]:+.3f} [{r[k][1]:+.3f}, {r[k][2]:+.3f}]" for k in ["mean_macro_f1", "band_acc", "under_rate", "score_mae"])
            lines.append(f"| {frac:.0%} | {'全部' if scope == 'all' else '去掉 derived'} | {cells} |")
    (OUT / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))

    # 图 3：两栏（平均宏 F1、低估率），全部测试集，种子 0–2 的均值 ± 标准差
    plt.rcParams.update({"font.family": "Arial", "font.size": 8, "axes.linewidth": 0.6})
    fig, axes = plt.subplots(1, 2, figsize=(6.6, 2.6))
    style = {"none": dict(color="#6E6E6E", ls="--", marker="s", label="without auxiliary task"),
             "aux": dict(color="#0072B2", ls="-", marker="o", label="with v3.1 auxiliary task")}
    for ax, key, ylab in [(axes[0], "mean_macro_f1", "Mean macro-F1"), (axes[1], "under_rate", "Under-estimation rate")]:
        for ver in ["none", "aux"]:
            g = data[(data.version == ver) & (data.scope == "all") & (data.seed <= 2)].groupby("n_labels")[key]
            m, s = g.mean(), g.std(ddof=1)
            ax.errorbar(m.index, m.values, yerr=s.values, capsize=2.5, lw=1.2, ms=4, **style[ver])
        ax.set_xscale("log")
        ticks = [round(N_TRAIN * f) for f in FRACS]
        ax.set_xticks(ticks)
        ax.set_xticklabels([f"{t:,}\n({f:.0%})" for t, f in zip(ticks, FRACS)], fontsize=7)
        ax.minorticks_off()
        ax.set_xlabel("v4.0 training labels")
        ax.set_ylabel(ylab)
        ax.grid(axis="y", lw=0.4, alpha=0.5)
        ax.spines[["top", "right"]].set_visible(False)
    axes[0].legend(frameon=False, fontsize=7, loc="lower right")
    axes[0].set_title("(a)", fontsize=8, loc="left")
    axes[1].set_title("(b)", fontsize=8, loc="left")
    fig.tight_layout()
    FIG.mkdir(parents=True, exist_ok=True)
    for ext in ("pdf", "png"):
        fig.savefig(FIG / f"fig3_label_efficiency.{ext}", dpi=300)


if __name__ == "__main__":
    main()
