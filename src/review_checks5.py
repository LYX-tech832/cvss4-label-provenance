"""第五份模拟审稿意见（10-01）建议的"标签替换"对照（CPU，几分钟，不重新训练）。

问题：派生标签使评测虚高，是"派生"本身造成的，还是 VulDB 这个来源本身的特点（漏洞类型单一、描述模板化）造成的？
做法：固定 CVE、描述、来源和模型预测，只换参照标签。
  在时间划分测试集中、非 derived 来源的双版本评分 CVE 上，同一批预测分别对照
  ① CNA 原始的 v4.0 向量；② 用规则 R 换算同一 CNA 的 v3.1 向量得到的 v4.0 向量（"假如这些标签是派生的"）。
  两套分数之差 = 派生本身带来的变化。报告全部、VulnCheck、不含 VulnCheck 三个口径；配对 bootstrap 1,000 次。
输出：results/review_checks/summary5.md
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded, fast_scores  # noqa: E402
from baselines_v0 import CUTOFF, M31, M40, evaluate, load, source_type_map  # noqa: E402
from rq1_stats import rule_convert  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
PRED = ROOT / "results" / "baselines_v0" / "predictions"
KEYS = ["mean_macro_f1", "band_acc", "under_rate"]


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    test = df[(df["pub"] >= CUTOFF) & df["has_v31"] & (df["label_type"] != "derived")].reset_index(drop=True)
    conv = [rule_convert({k: r["x31_" + k] for k in M31}) for _, r in test.iterrows()]
    test_r = test.copy()
    for k in M40:
        test_r["y_" + k] = [c[k] for c in conv]
    same = np.array([all(c[k] == test.at[i, "y_" + k] for k in M40) for i, c in enumerate(conv)])
    ids = test["cve_id"]
    models = {"TF-IDF + LR": [pd.read_parquet(PRED / "T2_temporal_tfidf_lr.parquet")],
              "DeBERTa（5 种子）": [pd.read_parquet(d / "pred_latent.parquet") for d in sorted(ENC.glob("T2_temporal_deberta-v3-base_none_e5_cwinv_sqrt_s[0-9]"))],
              "DeBERTa + v3.1 辅助（5 种子）": [pd.read_parquet(d / "pred_latent.parquet") for d in sorted(ENC.glob("T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s[0-9]"))],
              "流水线（TF-IDF，规则 R）": None}
    preds = {n: [p.set_index("cve_id").loc[ids].reset_index() for p in ps] for n, ps in models.items() if ps}
    t_orig, t_conv = Encoded(test, "y_"), Encoded(test_r, "y_")
    enc = {n: [Encoded(p) for p in ps] for n, ps in preds.items()}
    vc = (test["source"] == "VulnCheck").to_numpy()
    lines = ["# 标签替换对照（时间划分测试集，非 derived 来源的双版本评分 CVE；自动生成）\n",
             f"共 {len(test):,} 条（VulnCheck {int(vc.sum()):,}，其他 {int((~vc).sum()):,}）；其中原始 v4.0 向量本来就等于规则 R 换算结果的 {same.mean():.1%}。",
             "同一批预测分别对照：① CNA 原始 v4.0 标签；② 规则 R 换算同一 CNA 的 v3.1 得到的标签。差值 = ② − ①（配对 bootstrap 1,000 次，95% 区间）。\n"]
    rng = np.random.default_rng(0)
    for scope, m in [("全部", np.ones(len(test), bool)), ("VulnCheck", vc), ("不含 VulnCheck", ~vc)]:
        idx = np.flatnonzero(m)
        lines += [f"\n## {scope}（n = {len(idx):,}）\n", "| 模型 | 指标 | 对照原始标签 | 对照规则 R 标签 | 差值 [95%] |", "|---|---|---|---|---|"]
        for n, es in enc.items():
            def sc(tt, ix):
                rs = [fast_scores(tt, e, ix) for e in es]
                return {k: np.mean([r[k] for r in rs]) for k in KEYS}
            a, b = sc(t_orig, idx), sc(t_conv, idx)
            boots = []
            for _ in range(1000):
                ix = rng.choice(idx, size=len(idx), replace=True)
                x, y = sc(t_orig, ix), sc(t_conv, ix)
                boots.append([y[k] - x[k] for k in KEYS])
            boots = np.array(boots)
            for j, k in enumerate(KEYS):
                lines.append(f"| {n} | {k} | {a[k]:.3f} | {b[k]:.3f} | {b[k] - a[k]:+.3f} [{np.percentile(boots[:, j], 2.5):+.3f}, {np.percentile(boots[:, j], 97.5):+.3f}] |")
        # 逐指标准确率（TF-IDF）
        p = preds["TF-IDF + LR"][0].iloc[idx]
        lines += ["\nTF-IDF 逐指标准确率：原始标签 → 规则 R 标签\n", "| " + " | ".join(M40) + " |", "|" + "---|" * len(M40)]
        cells = []
        for k in M40:
            a_o = (p[k].to_numpy() == test["y_" + k].to_numpy()[idx]).mean()
            a_r = (p[k].to_numpy() == test_r["y_" + k].to_numpy()[idx]).mean()
            cells.append(f"{a_o:.3f} → {a_r:.3f}")
        lines.append("| " + " | ".join(cells) + " |")
    out = ROOT / "results" / "review_checks" / "summary5.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
