"""流水线基线（CPU）：描述 → v3.1（文本分类）→ v4.0（规则换算）。仿照 Vieira et al., IoT 39 (2026) 102038 的思路。

注意：这条路线完全不使用 v4.0 标签，只用"只有 v3.1 标签"的 CVE 训练阶段 1。
阶段 1：TF-IDF + LR，训练集 = 只有 v3.1、没有 CNA v4.0 的 CVE
        （时间划分：只取 2026 年前发布的；留一来源：去掉被留出来源的 CVE）
阶段 2：两种换算规则
        rule_R          我们的规则 R：AV/AC/PR 照抄，AT=N，UI: N→N、R→P，VC/VI/VA=C/I/A，S:C 时 SC/SI/SA 照抄 C/I/A
        vieira_like     与 R 相同，但 SC/SI/SA 一律为 N（Vieira 2026 原文说明其确定性映射把这三项设为 N）
        ⚠️ Vieira 的流水线后续还有基于候选分数的 ML 等级选择，只输出严重性等级，无法按向量复现，所以这里只是"近似"
评测：与 T2 相同的测试集，报告全部、去掉 derived、按标签类型三种口径
输出：results/pipeline_baseline/summary.md、metrics.json
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import CUTOFF, M31, M40, SEED, SHORT, evaluate, load, source_type_map  # noqa: E402
from pilot_transfer import v31_pool  # noqa: E402
from rq1_stats import rule_convert  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "results" / "pipeline_baseline"
SPLITS = ["temporal", "loso:VulnCheck", "loso:GitHub_M", "loso:VulDB"]


def stage1(pool, texts):
    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=3, max_features=300_000, sublinear_tf=True)
    x, xq = vec.fit_transform(pool["text"]), vec.transform(texts)
    out = {}
    for k in M31:
        out[k] = LogisticRegression(C=4.0, max_iter=3000, random_state=SEED).fit(x, pool["z_" + k].values).predict(xq)
        print("  阶段 1 完成指标", k, flush=True)
    return pd.DataFrame(out)


def convert(v31_df, subsequent_from_scope):
    rows = []
    for _, r in v31_df.iterrows():
        v4 = rule_convert({k: r[k] for k in M31})
        if not subsequent_from_scope:
            v4.update({"SC": "N", "SI": "N", "SA": "N"})
        rows.append(v4)
    return pd.DataFrame(rows)[M40]


def report(test, pred):
    types = test["source"].map(source_type_map()).fillna("other").values
    out = {}
    for scope, m in [("all", np.ones(len(test), bool)), ("non_derived", types != "derived")] + [(t, types == t) for t in ["derived", "independent", "v4_only", "other"]]:
        if m.sum() >= 30:
            r = evaluate(test[m].reset_index(drop=True), pred[m].reset_index(drop=True))
            out[scope] = {k: r[k] for k in SHORT} | {
                "v4_specific_f1": float(np.mean([r["per_metric"][k]["macro_f1"] for k in ["AT", "UI", "SC", "SI", "SA"]]))}
    return out


def main():
    df = load()
    results = {}
    for split in SPLITS:
        if split == "temporal":
            test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
            pool = v31_pool(before_cutoff=True)
        else:
            s = split.split(":", 1)[1]
            test = df[df["source"] == s].reset_index(drop=True)
            pool = v31_pool(before_cutoff=False)
            pool = pool[pool["cna_short_name"].fillna("UNKNOWN") != s]
        print(f"== {split}: 阶段 1 训练 {len(pool):,} 条，测试 {len(test):,} 条", flush=True)
        v31_pred = stage1(pool, list(test["text"]))
        results[split] = {"n_pool": len(pool), "n_test": len(test)}
        for name, sub in [("rule_R", True), ("vieira_like", False)]:
            results[split][name] = report(test, convert(v31_pred, sub))
            a = results[split][name]["all"]
            print(f"  {name}: 平均F1 {a['mean_macro_f1']:.3f} 全对 {a['exact_match']:.3f} 等级准确率 {a['band_acc']:.3f} 低估率 {a['under_rate']:.3f}", flush=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "metrics.json").write_text(json.dumps(results, indent=1, ensure_ascii=False), encoding="utf-8")
    lines = ["# 流水线基线：描述 → v3.1（TF-IDF+LR）→ v4.0（规则换算）；不使用任何 v4.0 标签\n",
             "单元格 = 平均F1 / 全对 / 等级准确率 / 低估率\n",
             "| 划分 | 换算 | 全部 | 去掉 derived | independent | v4_only | other |", "|---|---|---|---|---|---|---|"]
    for split, r in results.items():
        for name in ["rule_R", "vieira_like"]:
            cells = []
            for scope in ["all", "non_derived", "independent", "v4_only", "other"]:
                x = r[name].get(scope)
                cells.append(f"{x['mean_macro_f1']:.3f} / {x['exact_match']:.3f} / {x['band_acc']:.3f} / {x['under_rate']:.3f}" if x else "-")
            lines.append(f"| {split} | {name} | " + " | ".join(cells) + " |")
    (OUT_DIR / "summary.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
