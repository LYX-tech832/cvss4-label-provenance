"""对照实验：有监督基线去掉 CWE 编号、只用描述（CPU）。

背景：有监督方法的输入是"描述 + CWE 编号"（baselines_v0.load() 里的 text 列），而 AutoCVSS 大模型基线按原做法只看描述。
这里用同一个 TF-IDF+LR（超参数与 baselines_v0 相同）只用描述重新训练，量化 CWE 编号带来的差别。
划分：T2 时间划分（2026 年以前训练，2026 年测试）。
输出：results/ablation_desc_only/（预测文件 + summary.md）；compare_llm_baseline.py 会自动加入"TF-IDF+LR（只用描述）"。
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import CUTOFF, evaluate, load, pred_tfidf_lr, source_type_map  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "ablation_desc_only"
TYPES = ["derived", "independent", "v4_only", "other"]
V4_SPECIFIC = ["AT", "UI", "SC", "SI", "SA"]
COLS = [("mean_macro_f1", "meanF1"), ("v4_specific_f1", "v4F1"), ("exact_match", "exact"), ("score_mae", "MAE"),
        ("band_acc", "band"), ("under_rate", "under"), ("hc_recall", "HC-rec")]


def scores(true_df, pred_df):
    r = evaluate(true_df.reset_index(drop=True), pred_df.reset_index(drop=True))
    r["v4_specific_f1"] = float(np.mean([r["per_metric"][k]["macro_f1"] for k in V4_SPECIFIC]))
    return r


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    df["has_cwe"] = (df["cwe_cna"].map(len) + df["cwe_adp"].map(len)) > 0
    df["text"] = df["description"].str.strip()  # 去掉 CWE 编号，只留描述
    train, test = df[df["pub"] < CUTOFF], df[df["pub"] >= CUTOFF].reset_index(drop=True)
    print(f"训练 {len(train):,} 条，测试 {len(test):,} 条；有 CWE 编号的比例：训练 {train['has_cwe'].mean():.1%}，测试 {test['has_cwe'].mean():.1%}", flush=True)

    pred = pred_tfidf_lr(train, test, with_v31=False).reset_index(drop=True)
    OUT.mkdir(parents=True, exist_ok=True)
    pred.assign(cve_id=test["cve_id"].values, source=test["source"].values).to_parquet(OUT / "T2_temporal_tfidf_lr_desc_only.parquet", index=False)
    ref = pd.read_parquet(ROOT / "results/baselines_v0/predictions/T2_temporal_tfidf_lr.parquet").set_index("cve_id").loc[test["cve_id"]].reset_index()

    lines = ["# 对照实验：TF-IDF+LR 只用描述 vs 描述 + CWE 编号（T2 时间划分，自动生成）\n",
             f"- 训练 {len(train):,} 条（2026 年以前），测试 {len(test):,} 条（2026 年）；"
             f"有 CWE 编号的比例：训练 {train['has_cwe'].mean():.1%}，测试 {test['has_cwe'].mean():.1%}",
             "- 超参数与 baselines_v0 相同，只改输入文本；单次运行（逻辑回归是确定性的）\n",
             "| 范围 | 输入 | " + " | ".join(c for _, c in COLS) + " |", "|---|---|" + "---|" * len(COLS)]
    for scope in ["全部测试集"] + TYPES + ["有 CWE", "无 CWE"]:
        m = {"全部测试集": np.ones(len(test), bool), "有 CWE": test["has_cwe"].values,
             "无 CWE": ~test["has_cwe"].values}.get(scope, (test["label_type"] == scope).values)
        if m.sum() < 30:
            continue
        for name, p in [("描述 + CWE", ref), ("只用描述", pred)]:
            r = scores(test[m], p[m])
            lines.append(f"| {scope}（n={m.sum():,}） | {name} | " + " | ".join(f"{r[k]:.3f}" for k, _ in COLS) + " |")
    (OUT / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
