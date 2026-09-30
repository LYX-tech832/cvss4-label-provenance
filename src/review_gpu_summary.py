"""汇总回应审稿意见的 GPU 实验（CPU，几分钟）：scripts/run_review_gpu.sh 的三项，T2 时间划分，种子 0–2。

1. 训练轮数：无辅助 / v3.1 辅助训练 10 轮与 5 轮（W4 主实验的同样种子）对比；10 轮时辅助任务的增益；最佳轮次。
2. 伪标签对照（pseudo）：与 v3.1 辅助用同一批 60,000 条辅助样本，只是换成规则 R 换算的 v4 伪标签直接监督 v4 头。
3. DeBERTa 版流水线（v31only）：只用这批样本训练 v3.1 头，再按规则 R 换算；与 TF-IDF 版流水线、v3.1 辅助模型对比。
差值为配对 bootstrap（测试 CVE 重抽样 1,000 次，每次对各版本的种子取平均），口径：全部测试集、去掉 derived。
输出：results/review_gpu/summary.md
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import BOOT_KEYS, metrics, paired_bootstrap  # noqa: E402
from baselines_v0 import M40, evaluate, load, source_type_map  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
OUT = ROOT / "results" / "review_gpu"
SEEDS = [0, 1, 2]
STEM = "T2_temporal_deberta-v3-base_none"
VERSIONS = {
    "无辅助（5 轮）": "_e5_cwinv_sqrt", "v3.1 辅助（5 轮）": "_aux_e5_cwinv_sqrt",
    "无辅助（10 轮）": "_e10_cwinv_sqrt", "v3.1 辅助（10 轮）": "_aux_e10_cwinv_sqrt",
    "伪标签（5 轮）": "_pseudo_e5_cwinv_sqrt", "DeBERTa 流水线（5 轮）": "_v31only_e5",
}
KEYS = ["mean_macro_f1", "exact_match", "score_mae", "band_acc", "under_rate", "hc_recall"]


def dirs(tag):
    return {s: ENC / f"{STEM}{tag}_s{s}" for s in SEEDS if (ENC / f"{STEM}{tag}_s{s}" / "pred_latent.parquet").exists()}


def per_metric(d, df, mask_nd):
    p = pd.read_parquet(d / "pred_latent.parquet")
    t = df.set_index("cve_id").loc[p["cve_id"]].reset_index()
    out = {}
    for scope, m in [("all", np.ones(len(t), bool)), ("non_derived", (t["label_type"] != "derived").to_numpy())]:
        r = evaluate(t[m].reset_index(drop=True), p[m].reset_index(drop=True))
        out[scope] = {k: r["per_metric"][k]["macro_f1"] for k in M40}
    return out


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    runs = {v: dirs(tag) for v, tag in VERSIONS.items()}
    lines = ["# 回应审稿意见的 GPU 实验（T2 时间划分，种子 0–2；自动生成）\n",
             "已完成的运行：" + "；".join(f"{v} {len(r)}/3" for v, r in runs.items()) + "\n"]
    have = {v: r for v, r in runs.items() if r}

    for scope, name in [("all", "全部测试集（21,900）"), ("non_derived", "去掉 derived（16,749）")]:
        lines += [f"\n## 各版本均值 ± 标准差：{name}\n", "| 版本 | 种子数 | " + " | ".join(KEYS) + " | 最佳轮次 |", "|---|---|" + "---|" * (len(KEYS) + 1)]
        for v, r in have.items():
            ms = [metrics(d, df)[scope] for d in r.values()]
            best = [json.loads((d / "results.json").read_text(encoding="utf-8"))["best_epoch"] + 1 for d in r.values()]
            n_ep = len(json.loads((next(iter(r.values())) / "results.json").read_text(encoding="utf-8"))["val_log"])
            lines.append(f"| {v} | {len(ms)} | " + " | ".join(f"{np.mean([m[k] for m in ms]):.3f} ± {np.std([m[k] for m in ms], ddof=1) if len(ms) > 1 else 0:.3f}" for k in KEYS)
                         + f" | {', '.join(map(str, best))} / {n_ep} |")

    pairs = [("v3.1 辅助（10 轮）", "无辅助（10 轮）"), ("v3.1 辅助（5 轮）", "无辅助（5 轮）"),
             ("无辅助（10 轮）", "无辅助（5 轮）"), ("v3.1 辅助（10 轮）", "v3.1 辅助（5 轮）"),
             ("伪标签（5 轮）", "无辅助（5 轮）"), ("v3.1 辅助（5 轮）", "伪标签（5 轮）"),
             ("DeBERTa 流水线（5 轮）", "无辅助（5 轮）"), ("v3.1 辅助（5 轮）", "DeBERTa 流水线（5 轮）")]
    lines += ["\n## 配对 bootstrap：A − B（种子 0–2 各自平均；95% 区间）\n",
              "| A − B | 口径 | 平均宏 F1 差 | 等级准确率差 | 低估率差 | 分数 MAE 差 |", "|---|---|---|---|---|---|"]
    for a, b in pairs:
        if a in have and b in have:
            res = paired_bootstrap(df, have[b], have[a])
            for scope in ["all", "non_derived"]:
                r = res[scope]
                lines.append(f"| {a} − {b} | {'全部' if scope == 'all' else '去掉 derived'} | " +
                             " | ".join(f"{r[k][0]:+.3f} [{r[k][1]:+.3f}, {r[k][2]:+.3f}]" for k in BOOT_KEYS) + " |")

    lines += ["\n## 逐指标宏 F1（全部测试集 / 去掉 derived；种子平均）\n", "| 版本 | " + " | ".join(M40) + " |", "|---|" + "---|" * len(M40)]
    for v, r in have.items():
        pm = [per_metric(d, df, None) for d in r.values()]
        lines.append(f"| {v} | " + " | ".join(f"{np.mean([x['all'][k] for x in pm]):.3f} / {np.mean([x['non_derived'][k] for x in pm]):.3f}" for k in M40) + " |")

    pl = json.loads((ROOT / "results" / "pipeline_baseline" / "metrics.json").read_text(encoding="utf-8"))["temporal"]["rule_R"]
    lines += ["\n## 参照：TF-IDF 版流水线（规则 R；results/pipeline_baseline）\n",
              "| 口径 | 平均宏 F1 | 全对 | MAE | 等级准确率 | 低估率 | H+C 召回 |", "|---|---|---|---|---|---|---|"]
    for scope in ["all", "non_derived"]:
        x = pl[scope]
        lines.append(f"| {scope} | {x['mean_macro_f1']:.3f} | {x['exact_match']:.3f} | {x['score_mae']:.3f} | {x['band_acc']:.3f} | {x['under_rate']:.3f} | {x['hc_recall']:.3f} |")

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
