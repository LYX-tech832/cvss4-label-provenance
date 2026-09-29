"""大模型基线与我们的方法在同一批测试 CVE 上的对比（CPU）。

读取 AutoCVSS+LLM 基线的预测（run_autocvss_baseline.py 的输出目录），把其他方法的测试集预测限制到同一批 CVE 上，
用同一个 evaluate() 计算指标，按标签类型（derived / independent / v4_only / other）分组报告。
另做一个敏感性分析：把 LLM 回答 DONT_KNOW（或调用失败）的指标改为训练集众数（AutoCVSS 原做法是改为最保守标签）。
注意：LLM 样本按标签类型分层抽样，"样本整体"一行不代表测试集的真实分布，主要看分组结果。
W4 结果取回本机后（results/encoder/selected_config.json 存在），会自动加入按验证集选定配置的全部种子（取平均）。
输出：<LLM 运行目录>/compare.md
用法：python src/compare_llm_baseline.py [--llm_dir results/autocvss_baseline/deepseek-v4-pro_DTD_s0]
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import CUTOFF, M40, evaluate, load, source_type_map  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
TYPES = ["derived", "independent", "v4_only", "other"]
V4_SPECIFIC = ["AT", "UI", "SC", "SI", "SA"]
COLS = [("mean_macro_f1", "meanF1"), ("v4_specific_f1", "v4F1"), ("exact_match", "exact"), ("score_mae", "MAE"),
        ("band_acc", "band"), ("under_rate", "under"), ("hc_recall", "HC-rec")]


def other_methods():
    """T2 时间划分上已保存测试集预测的方法：名称 → [预测文件]（多个种子时对各种子的指标取平均）"""
    m = {"多数类": [ROOT / "results/baselines_v0/predictions/T2_temporal_majority.parquet"],
         "TF-IDF+LR": [ROOT / "results/baselines_v0/predictions/T2_temporal_tfidf_lr.parquet"],
         "TF-IDF+LR（只用描述，与 LLM 输入相同）": [ROOT / "results/ablation_desc_only/T2_temporal_tfidf_lr_desc_only.parquet"],
         "DeBERTa（W3，3 轮，种子 0）": [ENC / "T2_temporal_deberta-v3-base_none_s0/pred_latent.parquet"],
         "DeBERTa+v3.1 辅助（W3，3 轮，种子 0）": [ENC / "T2_temporal_deberta-v3-base_none_aux_s0/pred_latent.parquet"]}
    sel = ENC / "selected_config.json"
    if sel.exists():
        for ver, c in json.loads(sel.read_text(encoding="utf-8")).items():
            files = sorted(ENC.glob(c["run"].rsplit("_s", 1)[0] + "_s*/pred_latent.parquet"))
            if files:
                m[f"DeBERTa{'+v3.1 辅助' if ver == 'aux' else ''}（W4 选定配置，{len(files)} 个种子）"] = files
    return {k: [f for f in v if f.exists()] for k, v in m.items() if any(f.exists() for f in v)}


def scores(true_df, pred_df):
    r = evaluate(true_df.reset_index(drop=True), pred_df.reset_index(drop=True))
    r["v4_specific_f1"] = float(np.mean([r["per_metric"][k]["macro_f1"] for k in V4_SPECIFIC]))
    return {k: r[k] for k, _ in COLS}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--llm_dir", default=str(ROOT / "results" / "autocvss_baseline" / "deepseek-v4-pro_DTD_s0"))
    args = ap.parse_args()
    llm_dir = Path(args.llm_dir)
    llm = pd.read_parquet(llm_dir / "predictions.parquet")
    info = json.loads((llm_dir / "results.json").read_text(encoding="utf-8"))

    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    test = df.set_index("cve_id").loc[llm["cve_id"]].reset_index()

    # 敏感性分析：DONT_KNOW / 调用失败 → 训练集众数（只改我们自己的后处理，不重新调用 LLM）
    raw = [json.loads(line) for line in (llm_dir / "raw.jsonl").read_text(encoding="utf-8").splitlines()]
    unknown = {(r["cve_id"], r["metric"]) for r in raw if r["label"] in (None, "DONT_KNOW")}
    train = df[df["pub"] < CUTOFF]
    majority = {k: train["y_" + k].mode()[0] for k in M40}
    alt = llm.copy()
    pos = {c: i for i, c in enumerate(alt["cve_id"])}
    for cve, k in unknown:
        if cve in pos:
            alt.iloc[pos[cve], alt.columns.get_loc(k)] = majority[k]

    preds = {f"AutoCVSS + {info['model']}（DONT_KNOW→最保守，原做法）": [llm],
             f"AutoCVSS + {info['model']}（DONT_KNOW→训练集众数，敏感性分析）": [alt]}
    # 其他大模型（如本地 Qwen3-8B）：必须与主运行是同一批 CVE
    for d in sorted(llm_dir.parent.glob("*_DTD_s0")):
        if d == llm_dir or not (d / "predictions.parquet").exists():
            continue
        o = pd.read_parquet(d / "predictions.parquet")
        if set(o["cve_id"]) != set(llm["cve_id"]):
            print(f"⚠️ {d.name} 的 CVE 与主运行不一致，跳过")
            continue
        preds[f"AutoCVSS + {json.loads((d / 'results.json').read_text(encoding='utf-8'))['model']}（原做法）"] = \
            [o.set_index("cve_id").loc[llm["cve_id"]].reset_index()]
    for name, files in other_methods().items():
        preds[name] = [pd.read_parquet(f).set_index("cve_id").loc[test["cve_id"]].reset_index() for f in files]

    lines = [f"# 大模型基线对比（同一批 {len(test):,} 条测试 CVE，自动生成）\n",
             f"- LLM：{info['model']}，AutoCVSS {info['prompt']} 提示（无 CoT），思考模式 {info.get('thinking')}；"
             f"依赖版本 {info.get('versions')}",
             f"- 样本按标签类型分层抽样：{test['label_type'].value_counts().to_dict()}。"
             "\"样本整体\"不代表测试集的真实分布，**主要看分组结果**",
             "- 监督方法都只用 2026 年以前的数据训练（时间划分），LLM 为零样本；W3 的 DeBERTa 是单种子、3 轮、未调参",
             f"- LLM 回答 DONT_KNOW 或调用失败的比例（按指标）：{ {k: round(v, 3) for k, v in info['fallback_rate'].items()} }",
             f"- token 用量：{info.get('usage_total')}\n",
             "| 范围 | 方法 | " + " | ".join(c for _, c in COLS) + " |",
             "|---|---|" + "---|" * len(COLS)]
    for scope in ["样本整体"] + TYPES:
        m = np.ones(len(test), bool) if scope == "样本整体" else (test["label_type"] == scope).values
        if m.sum() < 30:
            continue
        for name, plist in preds.items():
            rs = [scores(test[m], p[m]) for p in plist]
            avg = {k: float(np.mean([r[k] for r in rs])) for k, _ in COLS}
            lines.append(f"| {scope}（n={m.sum()}） | {name} | " + " | ".join(f"{avg[k]:.3f}" for k, _ in COLS) + " |")
    out = llm_dir / "compare.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\n已写入 {out}")


if __name__ == "__main__":
    main()
