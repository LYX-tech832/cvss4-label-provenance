"""按来源等权时，方法的排名（10-05，CPU，约 3 分钟）。

外部评估指出：时间划分的非派生测试集里 VulnCheck 和 GitHub 占 59.6%，"非派生"的结果很大程度上是这两个来源的结果。
表 S31 的来源宏平均没有包含流水线，所以"分类器与流水线的排名翻转"在每个来源等权的口径下是否成立，此前没有检查过。
这里对每个测试 CVE ≥ 30（或 ≥ 100）条的来源分别算指标，再等权平均；差值的区间来自对来源的重抽样（2,000 次）。
输出：results/review_checks/summary15.md
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded, fast_scores  # noqa: E402
from baselines_v0 import CUTOFF, load  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
BASE = ROOT / "results" / "baselines_v0" / "predictions"
PIPE = ROOT / "results" / "pipeline_baseline" / "predictions"
OUT = ROOT / "results" / "review_checks" / "summary15.md"
KEYS = ("mean_macro_f1", "band_acc", "under_rate")
REF = "流水线（规则 R）"
rng = np.random.default_rng(0)


def main():
    df = load()
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    ids = test["cve_id"]
    t = Encoded(test, "y_")

    def enc(path):
        return Encoded(pd.read_parquet(path).set_index("cve_id").loc[ids].reset_index())
    methods = {"TF-IDF + LR": [enc(BASE / "T2_temporal_tfidf_lr.parquet")],
               REF: [enc(PIPE / "T2_temporal_pipeline_rule_R.parquet")],
               "流水线（SC/SI/SA = N）": [enc(PIPE / "T2_temporal_pipeline_scsisa_N.parquet")],
               "DeBERTa（25 轮）": [enc(ENC / f"T2_temporal_deberta-v3-base_none_e25_cwinv_sqrt_s{s}" / "pred_latent.parquet") for s in range(5)],
               "DeBERTa + 辅助": [enc(ENC / f"T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s{s}" / "pred_latent.parquet") for s in range(5)]}
    src = test["source"].to_numpy()
    counts = test["source"].value_counts()

    def score(m, idx):
        rs = [fast_scores(t, e, idx) for e in methods[m]]
        return {k: float(np.mean([r[k] for r in rs])) for k in KEYS}

    lines = ["# 按来源等权时方法的排名（时间划分测试集，自动生成）\n",
             "## 0. 对照：按 CVE 合并（论文表 7 的口径）\n", "| 范围 | 方法 | 平均宏 F1 | 等级准确率 | 低估率 |", "|---|---|---|---|---|"]
    for name, idx in [("全部（21,900）", np.arange(len(test))), ("非 VulDB（16,749）", np.flatnonzero(src != "VulDB"))]:
        for m in methods:
            s = score(m, idx)
            lines.append(f"| {name} | {m} | " + " | ".join(f"{s[k]:.3f}" for k in KEYS) + " |")

    for min_n in (30, 100):
        keep_all = [s for s, n in counts.items() if n >= min_n]
        per = {m: {s: score(m, np.flatnonzero(src == s)) for s in keep_all} for m in methods}
        for label, keep in [("全部来源", keep_all), ("不含 VulDB", [s for s in keep_all if s != "VulDB"])]:
            n_cve = int(sum(counts[s] for s in keep))
            lines += [f"\n## 测试 CVE ≥ {min_n} 条的来源，{label}：{len(keep)} 个（{n_cve:,} 条），每个来源等权\n",
                      "| 方法 | 平均宏 F1 | 等级准确率 | 低估率 |", "|---|---|---|---|"]
            for m in methods:
                lines.append(f"| {m} | " + " | ".join(f"{np.mean([per[m][s][k] for s in keep]):.3f}" for k in KEYS) + " |")
            lines += [f"\n与{REF}的差（方法 − 流水线；区间：对来源重抽样 2,000 次）\n",
                      "| 方法 | 等级准确率差 | 方法更高的来源数 | 平均宏 F1 差 | 方法更高的来源数 |", "|---|---|---|---|---|"]
            for m in methods:
                if m == REF:
                    continue
                cells = []
                for k in ("band_acc", "mean_macro_f1"):
                    d = np.array([per[m][s][k] - per[REF][s][k] for s in keep])
                    bs = np.array([d[rng.integers(len(keep), size=len(keep))].mean() for _ in range(2000)])
                    cells += [f"{d.mean():+.3f} [{np.percentile(bs, 2.5):+.3f}, {np.percentile(bs, 97.5):+.3f}]", f"{int((d > 0).sum())} / {len(keep)}"]
                lines.append(f"| {m} | " + " | ".join(cells) + " |")
        if min_n == 100:
            lines += ["\n### 各来源的等级准确率（≥ 100 条）：TF-IDF + LR / 流水线（规则 R）/ DeBERTa + 辅助\n", "| 来源 | n | TF-IDF + LR | 流水线（规则 R） | DeBERTa + 辅助 |", "|---|---|---|---|---|"]
            for s in keep_all:
                lines.append(f"| {s} | {counts[s]:,} | {per['TF-IDF + LR'][s]['band_acc']:.3f} | {per[REF][s]['band_acc']:.3f} | {per['DeBERTa + 辅助'][s]['band_acc']:.3f} |")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\n已写入 {OUT}")


if __name__ == "__main__":
    main()
