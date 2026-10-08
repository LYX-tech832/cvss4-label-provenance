"""通读 PDF 后补的两项（10-05，CPU，约 2 分钟）：

1. 大模型样本（2,000 条）上各方法的低估率 / 高危召回率，按整体、非 derived 和四种标签类型分组。
   论文 7.5 节引用了大模型的这两个指标，但原来没有任何表给出（表 9 只有平均宏 F1 和等级准确率）。→ 补充材料表 S37
   同时输出平均宏 F1 / 等级准确率，用来核对与表 9 一致。
2. 一个派生标签的具体例子：VulDB 最常见的 v3.1 向量对应多少种 v4.0 向量，与 VulnCheck 对比。→ 4.3 节
输出：results/review_checks/summary14.md
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import CUTOFF, M31, M40, evaluate, load, source_type_map  # noqa: E402
from rq1_stats import rule_convert  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
LLM = ROOT / "results" / "autocvss_baseline"
OUT = ROOT / "results" / "review_checks" / "summary14.md"
STEM = "T2_temporal_deberta-v3-base_none"
SCOPES = [("样本整体", None), ("非 derived", "nd"), ("derived", "derived"), ("undetected", "independent"), ("v4-only", "v4_only"), ("other", "other")]


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    main_dir = LLM / "deepseek-v4-pro_DTD_s0"
    llm = pd.read_parquet(main_dir / "predictions.parquet")
    ids = llm["cve_id"]
    test = df.set_index("cve_id").loc[ids].reset_index()
    lt = test["label_type"].to_numpy()

    # "don't know" → 训练集众数（与 compare_llm_baseline.py 相同的后处理）
    raw = [json.loads(line) for line in (main_dir / "raw.jsonl").read_text(encoding="utf-8").splitlines()]
    unknown = {(r["cve_id"], r["metric"]) for r in raw if r["label"] in (None, "DONT_KNOW")}
    train = df[df["pub"] < CUTOFF]
    majority = {k: train["y_" + k].mode()[0] for k in M40}
    alt = llm.copy()
    pos = {c: i for i, c in enumerate(alt["cve_id"])}
    for cve, k in unknown:
        if cve in pos:
            alt.iloc[pos[cve], alt.columns.get_loc(k)] = majority[k]

    def rd(p):
        return pd.read_parquet(p).set_index("cve_id").loc[ids].reset_index()

    methods = [("AutoCVSS + DeepSeek-V4-Pro", [llm]),
               ("– \"don't know\" → 训练集众数", [alt]),
               ("AutoCVSS + Qwen3-8B", [rd(LLM / "Qwen3-8B_DTD_s0" / "predictions.parquet")]),
               ("多数类", [rd(ROOT / "results/baselines_v0/predictions/T2_temporal_majority.parquet")]),
               ("TF-IDF + LR", [rd(ROOT / "results/baselines_v0/predictions/T2_temporal_tfidf_lr.parquet")]),
               ("TF-IDF + LR（只用描述）", [rd(ROOT / "results/ablation_desc_only/T2_temporal_tfidf_lr_desc_only.parquet")]),
               ("DeBERTa（25 轮，5 种子）", [rd(ENC / f"{STEM}_e25_cwinv_sqrt_s{s}" / "pred_latent.parquet") for s in range(5)]),
               ("DeBERTa + v3.1 辅助（5 种子）", [rd(ENC / f"{STEM}_aux_e5_cwinv_sqrt_s{s}" / "pred_latent.parquet") for s in range(5)])]

    res = {}
    for name, plist in methods:
        for scope, key in SCOPES:
            m = np.ones(len(test), bool) if key is None else (lt != "derived") if key == "nd" else (lt == key)
            rs = [evaluate(test[m].reset_index(drop=True), p[m].reset_index(drop=True)) for p in plist]
            res[(name, scope)] = {k: float(np.mean([r[k] for r in rs])) for k in ("mean_macro_f1", "band_acc", "under_rate", "hc_recall")}
    n = {scope: int((np.ones(len(test), bool) if key is None else (lt != "derived") if key == "nd" else (lt == key)).sum()) for scope, key in SCOPES}
    head = "| 方法 | " + " | ".join(f"{s}（{n[s]:,}）" for s, _ in SCOPES) + " |"
    lines = ["# 大模型样本上的决策指标，以及一个派生标签的例子（自动生成）\n",
             "## 1. 低估率 / 高危召回率（大模型样本 2,000 条；DeBERTa 为 5 个种子的平均）→ 表 S37\n", head, "|---|" + "---|" * len(SCOPES)]
    for name, _ in methods:
        lines.append(f"| {name} | " + " | ".join(f"{res[(name, s)]['under_rate']:.3f} / {res[(name, s)]['hc_recall']:.3f}" for s, _ in SCOPES) + " |")
    lines += ["\n核对用：平均宏 F1 / 等级准确率（应与论文表 9 一致）\n", head, "|---|" + "---|" * len(SCOPES)]
    for name, _ in methods:
        lines.append(f"| {name} | " + " | ".join(f"{res[(name, s)]['mean_macro_f1']:.3f} / {res[(name, s)]['band_acc']:.3f}" for s, _ in SCOPES) + " |")

    # 2 例子
    d = df[df["has_v31"]].copy()
    d["v31"] = d[["x31_" + k for k in M31]].apply(lambda r: "/".join(f"{k}:{v}" for k, v in zip(M31, r)), axis=1)
    d["v40"] = d[["y_" + k for k in M40]].apply(lambda r: "/".join(f"{k}:{v}" for k, v in zip(M40, r)), axis=1)
    vul = d[d["source"] == "VulDB"]
    top = vul["v31"].value_counts()
    lines += ["\n## 2. 派生标签的例子（全部数据中有同来源 v3.1 向量的 CVE）→ 4.3 节\n",
              "| 来源 | v3.1 向量 | 条数 | 对应的 v4.0 向量种数 | 最常见的 v4.0 向量 | 其条数（占比） | 规则 R 的结果 |", "|---|---|---|---|---|---|---|"]
    for v31 in top.index[:3]:
        r = rule_convert(dict(kv.split(":") for kv in v31.split("/")))
        rule = "/".join(f"{k}:{r[k]}" for k in M40)
        for src in ["VulDB", "VulnCheck", "GitHub_M"]:
            sub = d[(d["source"] == src) & (d["v31"] == v31)]
            if len(sub) == 0:
                lines.append(f"| {src} | {v31} | 0 | – | – | – | {rule} |")
                continue
            vc = sub["v40"].value_counts()
            lines.append(f"| {src} | {v31} | {len(sub):,} | {len(vc)} | {vc.index[0]} | {vc.iloc[0]:,}（{vc.iloc[0] / len(sub):.1%}） | {rule} |")
    lines.append(f"\nVulDB 共有 {len(vul):,} 条带同来源 v3.1 向量的 CVE，{vul['v31'].nunique()} 种 v3.1 向量、{vul['v40'].nunique()} 种 v4.0 向量。")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\n已写入 {OUT}")


if __name__ == "__main__":
    main()
