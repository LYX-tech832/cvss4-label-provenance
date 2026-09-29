"""大模型对比的配对 bootstrap 区间（CPU）：第 7.1 节表 9 与第 8.2 节"结论效度"用。

样本：compare_llm_baseline.py 用的同一批 2,000 条测试 CVE（按标签类型分层抽样：derived 300、independent 700、v4_only 500、other 500）。
方法：AutoCVSS + DeepSeek-V4-Pro（主运行：接口默认温度，DONT_KNOW → 最保守，即 AutoCVSS 原做法）、AutoCVSS + Qwen3-8B、
      TF-IDF+LR（描述 + CWE）、TF-IDF+LR（只用描述，与 LLM 输入相同）、DeBERTa 与 DeBERTa + v3.1 辅助（W4 选定配置，5 个种子）。
重抽样：在每个标签类型内有放回重抽样（各类型条数不变，与分层抽样的设计一致），默认 1,000 次；所有方法用同一批重抽样的 CVE（配对）；
        多种子的方法在每次重抽样中先按种子平均。区间为 95% 百分位区间。
口径：样本整体、去掉 derived、四个标签类型。指标与 evaluate() 同一口径（aggregate_seeds.fast_scores）。
注意：样本按类型分层，"样本整体"与"去掉 derived"两行不代表测试集的真实分布。
输出：results/autocvss_baseline/deepseek-v4-pro_DTD_s0/compare_bootstrap.md
"""

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import BOOT_KEYS, Encoded, fast_scores  # noqa: E402
from baselines_v0 import load, source_type_map  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
LLM = ROOT / "results" / "autocvss_baseline"
MAIN = LLM / "deepseek-v4-pro_DTD_s0"
TYPES = ["derived", "independent", "v4_only", "other"]
SCOPES = {"样本整体": TYPES, "去掉 derived": TYPES[1:], **{t: [t] for t in TYPES}}
METHODS = {"DeepSeek": [MAIN / "predictions.parquet"],
           "Qwen3-8B": [LLM / "Qwen3-8B_DTD_s0" / "predictions.parquet"],
           "TF-IDF": [ROOT / "results" / "baselines_v0" / "predictions" / "T2_temporal_tfidf_lr.parquet"],
           "TF-IDF（只用描述）": [ROOT / "results" / "ablation_desc_only" / "T2_temporal_tfidf_lr_desc_only.parquet"],
           "DeBERTa": sorted(ENC.glob("T2_temporal_deberta-v3-base_none_e5_cwinv_sqrt_s[0-9]/pred_latent.parquet")),
           "DeBERTa+辅助": sorted(ENC.glob("T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s[0-9]/pred_latent.parquet"))}
CONTRASTS = [("DeepSeek", "TF-IDF"), ("DeepSeek", "TF-IDF（只用描述）"), ("DeBERTa+辅助", "DeepSeek"),
             ("DeBERTa+辅助", "TF-IDF"), ("DeepSeek", "Qwen3-8B")]
NAMES = {"mean_macro_f1": "平均宏 F1", "band_acc": "等级准确率", "under_rate": "低估率", "score_mae": "分数 MAE"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--boot", type=int, default=1000, help="重抽样次数")
    args = ap.parse_args()
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    ids = pd.read_parquet(MAIN / "predictions.parquet")["cve_id"]
    truth = df.set_index("cve_id").loc[ids].reset_index()
    t = Encoded(truth, "y_")
    enc = {name: [Encoded(pd.read_parquet(f).set_index("cve_id").loc[ids].reset_index()) for f in files]
           for name, files in METHODS.items()}
    lt = truth["label_type"].to_numpy()
    rng = np.random.default_rng(0)

    def score_all(idx):
        """每个方法在这批 CVE 上的指标（多种子时先按种子平均）。"""
        out = {}
        for name, ps in enc.items():
            rs = [fast_scores(t, p, idx) for p in ps]
            out[name] = {k: float(np.mean([r[k] for r in rs])) for k in BOOT_KEYS}
        return out

    lines = [f"# 大模型对比的配对 bootstrap（同一批 {len(ids):,} 条测试 CVE；类型内重抽样 {args.boot:,} 次；95% 百分位区间；自动生成）\n",
             "方法的种子数：" + "、".join(f"{n} {len(ps)}" for n, ps in enc.items()) + "。"
             "样本按类型分层，\"样本整体\"与\"去掉 derived\"不代表测试集的真实分布。\n"]
    tab_m = ["\n## 各方法的点估计与 95% 区间\n", "| 口径 | 方法 | " + " | ".join(NAMES[k] for k in BOOT_KEYS) + " |", "|---|---|" + "---|" * len(BOOT_KEYS)]
    tab_c = ["\n## 两两差值（A − B）与 95% 区间\n", "| 口径 | A − B | " + " | ".join(NAMES[k] + "差" for k in BOOT_KEYS) + " |", "|---|---|" + "---|" * len(BOOT_KEYS)]
    for scope, types in SCOPES.items():
        strata = [np.flatnonzero(lt == ty) for ty in types]
        n = sum(len(s) for s in strata)
        point = score_all(np.concatenate(strata))
        boots = [score_all(np.concatenate([rng.choice(s, size=len(s), replace=True) for s in strata])) for _ in range(args.boot)]
        for name in enc:
            ci = {k: np.percentile([b[name][k] for b in boots], [2.5, 97.5]) for k in BOOT_KEYS}
            tab_m.append(f"| {scope}（n={n:,}） | {name} | " + " | ".join(
                f"{point[name][k]:.3f} [{ci[k][0]:.3f}, {ci[k][1]:.3f}]" for k in BOOT_KEYS) + " |")
        for a, b in CONTRASTS:
            ci = {k: np.percentile([bb[a][k] - bb[b][k] for bb in boots], [2.5, 97.5]) for k in BOOT_KEYS}
            tab_c.append(f"| {scope}（n={n:,}） | {a} − {b} | " + " | ".join(
                f"{point[a][k] - point[b][k]:+.3f} [{ci[k][0]:+.3f}, {ci[k][1]:+.3f}]" for k in BOOT_KEYS) + " |")
    lines += tab_c + ["\n区间不含 0 即表示在该口径上差异稳定。低估率和 MAE 越小越好。"] + tab_m
    out = MAIN / "compare_bootstrap.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
