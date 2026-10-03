"""第三轮审稿 M2（10-03）：把大模型的采样随机性算进"排名翻转"的置信区间（CPU，约 2 分钟）。

DeepSeek-V4-Pro 在同一批 2,000 条测试 CVE 上、按主运行的设置（接口默认采样）共跑了三遍：
主运行（9-26）和两遍完整重复（scripts/run_llm_fullreps.py，10-03）。比较对象：TF-IDF + LR（描述 + CWE）。
1. 每一遍各自的"DeepSeek − TF-IDF"差值（平均宏 F1、等级准确率）及三遍的标准差；
2. 三遍取平均后的差值，区间有两种：只对测试 CVE 重抽样（类型内，三遍固定）；
   两层重抽样（测试 CVE 在类型内重抽样 + 三遍运行有放回重抽样），后者计入了采样随机性；
3. 各遍之间严重性等级与完整向量的一致率。
输出：results/autocvss_baseline/reversal_runs.md
"""

import sys
from itertools import combinations
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded, fast_scores  # noqa: E402
from baselines_v0 import M40, load, source_type_map  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
LLM = ROOT / "results" / "autocvss_baseline"
RUNS = {"主运行（9-26）": "deepseek-v4-pro_DTD_s0", "完整重复 1（10-03）": "deepseek-v4-pro_DTD_s0_fullrep1", "完整重复 2（10-03）": "deepseek-v4-pro_DTD_s0_fullrep2"}
TYPES = ["derived", "independent", "v4_only", "other"]
SCOPES = {"样本整体": TYPES, "去掉 derived": TYPES[1:]}
B = 2000


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    ids = pd.read_parquet(LLM / RUNS["主运行（9-26）"] / "predictions.parquet")["cve_id"]
    truth = df.set_index("cve_id").loc[ids].reset_index()
    t = Encoded(truth, "y_")
    preds = {n: pd.read_parquet(LLM / d / "predictions.parquet").set_index("cve_id").loc[ids].reset_index() for n, d in RUNS.items()}
    runs = [Encoded(p) for p in preds.values()]
    tf = Encoded(pd.read_parquet(ROOT / "results" / "baselines_v0" / "predictions" / "T2_temporal_tfidf_lr.parquet").set_index("cve_id").loc[ids].reset_index())
    lt = truth["label_type"].to_numpy()
    rng = np.random.default_rng(0)
    lines = [f"# 排名翻转与大模型的采样随机性（同一批 {len(ids):,} 条测试 CVE，DeepSeek-V4-Pro 三遍运行；自动生成）\n"]

    def diff(idx, which):
        a = [fast_scores(t, runs[i], idx) for i in which]
        b = fast_scores(t, tf, idx)
        return (np.mean([x["mean_macro_f1"] for x in a]) - b["mean_macro_f1"], np.mean([x["band_acc"] for x in a]) - b["band_acc"])

    for scope, types in SCOPES.items():
        strata = [np.flatnonzero(lt == ty) for ty in types]
        idx = np.concatenate(strata)
        per = np.array([diff(idx, [i]) for i in range(3)])
        lines += [f"\n## {scope}（n = {len(idx):,}）：DeepSeek − TF-IDF\n", "| 运行 | 平均宏 F1 差 | 等级准确率差 |", "|---|---|---|"]
        for (name, _), d in zip(RUNS.items(), per):
            lines.append(f"| {name} | {d[0]:+.3f} | {d[1]:+.3f} |")
        lines.append(f"| 三遍的标准差 | {per[:, 0].std(ddof=1):.4f} | {per[:, 1].std(ddof=1):.4f} |")
        pt = diff(idx, [0, 1, 2])
        b1 = np.array([diff(np.concatenate([rng.choice(s, size=len(s), replace=True) for s in strata]), [0, 1, 2]) for _ in range(B)])
        b2 = np.array([diff(np.concatenate([rng.choice(s, size=len(s), replace=True) for s in strata]), list(rng.integers(0, 3, size=3))) for _ in range(B)])
        b0 = np.array([diff(np.concatenate([rng.choice(s, size=len(s), replace=True) for s in strata]), [0]) for _ in range(B)])
        ci = lambda x, j: f"[{np.percentile(x[:, j], 2.5):+.3f}, {np.percentile(x[:, j], 97.5):+.3f}]"  # noqa: E731
        lines += ["", "| 估计 | 平均宏 F1 差 | 等级准确率差 |", "|---|---|---|",
                  f"| 只用主运行，CVE 重抽样（论文原来的做法） | {per[0, 0]:+.3f} {ci(b0, 0)} | {per[0, 1]:+.3f} {ci(b0, 1)} |",
                  f"| 三遍平均，CVE 重抽样 | {pt[0]:+.3f} {ci(b1, 0)} | {pt[1]:+.3f} {ci(b1, 1)} |",
                  f"| 三遍平均，CVE 与运行两层重抽样 | {pt[0]:+.3f} {ci(b2, 0)} | {pt[1]:+.3f} {ci(b2, 1)} |"]

    lines += ["\n## 各遍之间的一致率（全部 2,000 条）\n", "| 运行对 | 严重性等级相同 | 完整向量相同 |", "|---|---|---|"]
    names = list(RUNS)
    for i, j in combinations(range(3), 2):
        band = (runs[i].band == runs[j].band).mean()
        vec = np.all([preds[names[i]][k].to_numpy() == preds[names[j]][k].to_numpy() for k in M40], axis=0).mean()
        lines.append(f"| {names[i]} / {names[j]} | {band:.1%} | {vec:.1%} |")
    out = LLM / "reversal_runs.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
