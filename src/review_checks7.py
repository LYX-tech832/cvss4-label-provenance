"""第二轮审稿（10-02，SCI第二轮审稿报告.md）的 CPU 核查（几分钟）：

1. 多向量记录（M9 / P7）：CNA 容器里有多个 v4.0（或 v3.1）向量的记录取第一个；排除这些记录后，
   主要方法在时间划分测试集上的结果变化多少，VulDB 的 FD_oos 变化多少。
2. LOSO 十轮比较的种子不确定性（M7 / P6）：辅助 5 轮 − 无辅助 10 轮的逐种子差值与 t 区间（4 自由度）。
输出：results/review_checks/summary7.md
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import CUTOFF, evaluate, load, source_type_map  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
OUT = ROOT / "results" / "review_checks" / "summary7.md"


def multi_vector_ids():
    raw = pd.read_parquet(ROOT / "data" / "processed" / "cve_records.parquet", columns=["cve_id", "cna_v40", "cna_v31"])
    n40 = raw["cna_v40"].map(len)
    n31 = raw["cna_v31"].map(len)
    return set(raw.loc[n40 > 1, "cve_id"]), set(raw.loc[(n40 >= 1) & (n31 > 1), "cve_id"])


def part1(lines):
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    multi40, multi31 = multi_vector_ids()
    multi = (multi40 | multi31) & set(df["cve_id"])
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    keep = ~test["cve_id"].isin(multi).to_numpy()
    lines += ["## 1. 多向量记录\n",
              f"v4.0 数据集中 CNA 给了多个 v4.0 向量的记录 {len(multi40 & set(df['cve_id'])):,} 条，"
              f"有 v4.0 且 CNA 给了多个 v3.1 向量的 {len(multi31 & set(df['cve_id'])):,} 条，合计（去重）{len(multi):,} 条；"
              f"其中时间划分测试集 {int((~keep).sum()):,} 条、训练与验证部分 {len(multi) - int((~keep).sum()):,} 条。\n",
              "排除这些测试 CVE 后（模型不重训；训练集里的这些记录照常使用），平均宏 F1 / 等级准确率的变化：\n",
              "| 方法 | 全部：原值 → 排除后 | 非 derived：原值 → 排除后 |", "|---|---|---|"]
    runs = {"TF-IDF + LR": [ROOT / "results" / "baselines_v0" / "predictions" / "T2_temporal_tfidf_lr.parquet"],
            "DeBERTa（5 种子）": [ENC / f"T2_temporal_deberta-v3-base_none_e5_cwinv_sqrt_s{s}" / "pred_latent.parquet" for s in range(5)],
            "DeBERTa + 辅助（5 种子）": [ENC / f"T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s{s}" / "pred_latent.parquet" for s in range(5)]}
    nd = (test["label_type"] != "derived").to_numpy()
    for name, paths in runs.items():
        ps = [pd.read_parquet(p).set_index("cve_id").loc[test["cve_id"]].reset_index() for p in paths]
        cells = []
        for m in [np.ones(len(test), bool), nd]:
            a = [evaluate(test[m].reset_index(drop=True), p[m].reset_index(drop=True)) for p in ps]
            b = [evaluate(test[m & keep].reset_index(drop=True), p[m & keep].reset_index(drop=True)) for p in ps]
            f = lambda rs, k: np.mean([r[k] for r in rs])  # noqa: E731
            cells.append(f"{f(a, 'mean_macro_f1'):.3f} / {f(a, 'band_acc'):.3f} → {f(b, 'mean_macro_f1'):.3f} / {f(b, 'band_acc'):.3f}")
        lines.append(f"| {name} | {cells[0]} | {cells[1]} |")
    by_src = test.loc[~keep, "source"].value_counts().head(8)
    lines.append("\n测试集中这些记录的来源（前 8）：" + "；".join(f"{s} {n}" for s, n in by_src.items()) + "\n")


def part2(lines):
    lines += ["\n## 2. LOSO：辅助 5 轮 − 无辅助 10 轮的逐种子差值（平均宏 F1）\n",
              "| 留出 | 逐种子差值（种子 0–4） | 均值 | t 区间（4 自由度） | 为正的种子数 |", "|---|---|---|---|---|"]
    for sp in ["VulnCheck", "GitHub_M", "VulDB"]:
        f = lambda tag, s: json.loads((ENC / f"T2_loso-{sp}_deberta-v3-base_none{tag}_s{s}" / "results.json").read_text(encoding="utf-8"))["latent"]["mean_macro_f1"]  # noqa: E731
        d = np.array([f("_aux_e5_cwinv_sqrt", s) - f("_e10_cwinv_sqrt", s) for s in range(5)])
        h = stats.t.ppf(0.975, 4) * d.std(ddof=1) / np.sqrt(5)
        lines.append(f"| {sp} | {', '.join(f'{x:+.3f}' for x in d)} | {d.mean():+.3f} | [{d.mean() - h:+.3f}, {d.mean() + h:+.3f}] | {int((d > 0).sum())} |")


def main():
    lines = ["# 第二轮审稿意见的 CPU 核查（自动生成）\n"]
    part1(lines)
    part2(lines)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
