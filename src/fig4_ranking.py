"""图 4：方法的排名随"用哪些标签打分"而改变（CPU，约 1 分钟）。

(a) 时间划分测试集上对 CNA 标签的等级准确率：全部标签 → 非 derived 标签。
(b) 测试集里有 NVD 自评 v3.1 向量的 CVE：对 CNA 标签的等级准确率 → 与 NVD 等级相同的比例。
四个方法：TF-IDF + LR、TF-IDF 流水线（规则 R，不用 v4.0 标签）、DeBERTa（25 轮）、DeBERTa + v3.1 辅助（各 5 个种子的平均）。
数值从保存的预测重算，应与论文表 7（Band 列）和补充表 S35 一致。
输出：paper/figures/fig4_ranking.pdf、.png、fig4_data.csv；并复制 pdf 到 paper/latex/figures。
"""

import shutil
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded  # noqa: E402
from baselines_v0 import CUTOFF, load, source_type_map  # noqa: E402
from nvd_reference import nvd_vectors  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
OUT = ROOT / "paper" / "figures"
METHODS = [("TF-IDF + LR", "#0072B2", "o", [ROOT / "results" / "baselines_v0" / "predictions" / "T2_temporal_tfidf_lr.parquet"]),
           ("TF-IDF pipeline (no v4.0 labels)", "#D55E00", "s", [ROOT / "results" / "pipeline_baseline" / "predictions" / "T2_temporal_pipeline_rule_R.parquet"]),
           ("DeBERTa", "#7F7F7F", "^", [ENC / f"T2_temporal_deberta-v3-base_none_e25_cwinv_sqrt_s{s}" / "pred_latent.parquet" for s in range(5)]),
           ("DeBERTa + v3.1 aux.", "#009E73", "D", [ENC / f"T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s{s}" / "pred_latent.parquet" for s in range(5)])]


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    t_band = Encoded(test, "y_").band
    nd = (test["label_type"] != "derived").to_numpy()
    nvd = nvd_vectors()
    has = test["cve_id"].isin(nvd).to_numpy()
    nvd_band = np.array([nvd[c][1] if c in nvd else -1 for c in test["cve_id"]])
    rows = []
    for name, _, _, files in METHODS:
        bands = [Encoded(pd.read_parquet(f).set_index("cve_id").loc[test["cve_id"]].reset_index()).band for f in files]
        acc = lambda m, ref: float(np.mean([(b[m] == ref[m]).mean() for b in bands]))  # noqa: E731
        rows.append({"method": name, "all": acc(np.ones(len(test), bool), t_band), "non_derived": acc(nd, t_band),
                     "nvd_subset_cna": acc(has, t_band), "nvd_subset_nvd": acc(has, nvd_band)})
    d = pd.DataFrame(rows)
    OUT.mkdir(parents=True, exist_ok=True)
    d.to_csv(OUT / "fig4_data.csv", index=False)
    print(d.round(3).to_string(index=False))
    print(f"测试集 {len(test):,} 条，非 derived {int(nd.sum()):,} 条，有 NVD 向量 {int(has.sum()):,} 条")

    plt.rcParams.update({"font.family": "Arial", "font.size": 8, "axes.linewidth": 0.6})
    fig, axes = plt.subplots(1, 2, figsize=(5.4, 2.7), sharey=True)
    panels = [("(a) Scored against CNA labels", "all", "non_derived", f"all labels\n({len(test):,})", f"non-derived\n({int(nd.sum()):,})"),
              (f"(b) Test CVEs with an NVD vector ({int(has.sum()):,})", "nvd_subset_cna", "nvd_subset_nvd", "against\nCNA labels", "against the\nNVD's rating")]
    def spread(values, gap=0.0125):
        """数值标签的纵向位置：相邻标签至少隔开 gap，避免重叠。"""
        order = np.argsort(values)
        pos = np.array(values, dtype=float)
        for a, b in zip(order[:-1], order[1:]):
            if pos[b] - pos[a] < gap:
                pos[b] = pos[a] + gap
        return pos - (pos.mean() - np.mean(values))

    for ax, (title, c0, c1, l0, l1) in zip(axes, panels):
        y0, y1 = spread(d[c0].to_numpy()), spread(d[c1].to_numpy())
        for i, ((name, color, marker, _), (_, r)) in enumerate(zip(METHODS, d.iterrows())):
            ax.plot([0, 1], [r[c0], r[c1]], color=color, marker=marker, markersize=4, linewidth=1.4, label=name)
            ax.text(-0.07, y0[i], f"{r[c0]:.3f}", ha="right", va="center", fontsize=6.5, color=color)
            ax.text(1.07, y1[i], f"{r[c1]:.3f}", ha="left", va="center", fontsize=6.5, color=color)
        ax.set_xlim(-0.45, 1.45)
        ax.set_xticks([0, 1])
        ax.set_xticklabels([l0, l1])
        ax.set_title(title, fontsize=8)
        for s in ("top", "right"):
            ax.spines[s].set_visible(False)
        ax.tick_params(length=2.5, width=0.6)
    axes[0].set_ylabel("Band accuracy / share of equal ratings")
    axes[0].set_ylim(0.43, 0.65)
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=2, frameon=False, fontsize=7, bbox_to_anchor=(0.5, -0.01), columnspacing=1.5, handlelength=2.2)
    fig.tight_layout(rect=(0, 0.11, 1, 1))
    for ext in ("pdf", "png"):
        fig.savefig(OUT / f"fig4_ranking.{ext}", dpi=300)
    latex_fig = ROOT / "paper" / "latex" / "figures"
    latex_fig.mkdir(parents=True, exist_ok=True)
    shutil.copy2(OUT / "fig4_ranking.pdf", latex_fig / "fig4_ranking.pdf")
    print("已保存 fig4_ranking.pdf / .png")


if __name__ == "__main__":
    main()
