"""主结果表（CPU）：T2 任务 4 种划分下各方法的表现（第 7.3 节表 7 的数据来源）。

方法：多数类、TF-IDF+LR（预测文件重算）、流水线（规则 R / Vieira 式，读 results/pipeline_baseline/metrics.json）、
      DeBERTa 无辅助 / 有 v3.1 辅助（W4 选定配置，5 个种子的均值 ± 标准差）。
口径：全部测试集；去掉 derived（留一 VulDB 的测试集全是 derived，没有此口径）。
输出：results/main_table.md
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import CUTOFF, evaluate, load, source_type_map  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
PRED = ROOT / "results" / "baselines_v0" / "predictions"
SPLITS = ["temporal", "loso:VulnCheck", "loso:GitHub_M", "loso:VulDB"]
V4S = ["AT", "UI", "SC", "SI", "SA"]
COLS = [("mean_macro_f1", "macro-F1"), ("v4_specific_f1", "v4-F1"), ("exact_match", "exact"), ("score_mae", "MAE"),
        ("band_acc", "band"), ("under_rate", "under"), ("hc_recall", "H+C rec.")]


def scores(t, p):
    r = evaluate(t.reset_index(drop=True), p.reset_index(drop=True))
    r["v4_specific_f1"] = float(np.mean([r["per_metric"][k]["macro_f1"] for k in V4S]))
    return {k: r[k] for k, _ in COLS}


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    pipe = json.loads((ROOT / "results" / "pipeline_baseline" / "metrics.json").read_text(encoding="utf-8"))
    lines = ["# 主结果表（T2，自动生成）\n", "DeBERTa 两行为 W4 选定配置 5 个种子的均值 ± 标准差；其余方法为确定性结果（单次）。\n"]
    for split in SPLITS:
        test = df[df["pub"] >= CUTOFF] if split == "temporal" else df[df["source"] == split.split(":")[1]]
        test = test.reset_index(drop=True)
        tag = split.replace(":", "-")
        for scope in ["all", "non_derived"]:
            m = np.ones(len(test), bool) if scope == "all" else (test["label_type"] != "derived").to_numpy()
            if m.sum() == 0:
                continue
            t = test[m].reset_index(drop=True)
            rows = {}
            for name, f in [("Majority", "majority"), ("TF-IDF + LR", "tfidf_lr")]:
                p = pd.read_parquet(PRED / f"T2_{tag}_{f}.parquet").set_index("cve_id").loc[t["cve_id"]].reset_index()
                rows[name] = {k: (v, None) for k, v in scores(t, p).items()}
            for name, key in [("Pipeline (rule R)", "rule_R"), ("Pipeline (SC/SI/SA = N)", "vieira_like")]:
                rows[name] = {k: (pipe[split][key][scope][k], None) for k, _ in COLS}
            for name, aux in [("DeBERTa", ""), ("DeBERTa + v3.1 auxiliary task", "_aux")]:
                runs = sorted(ENC.glob(f"T2_{tag}_deberta-v3-base_none{aux}_e5_cwinv_sqrt_s[0-9]"))
                res = []
                for d in runs:
                    p = pd.read_parquet(d / "pred_latent.parquet").set_index("cve_id").loc[t["cve_id"]].reset_index()
                    res.append(scores(t, p))
                rows[f"{name} ({len(runs)} seeds)"] = {k: (float(np.mean([r[k] for r in res])), float(np.std([r[k] for r in res], ddof=1)))
                                                      for k, _ in COLS}
            lines += [f"\n## {split}（{'全部测试集' if scope == 'all' else '去掉 derived'}，n = {len(t):,}）\n",
                      "| 方法 | " + " | ".join(c for _, c in COLS) + " |", "|---|" + "---|" * len(COLS)]
            for name, r in rows.items():
                lines.append(f"| {name} | " + " | ".join(f"{v:.3f}" + (f" ± {s:.3f}" if s is not None else "") for v, s in r.values()) + " |")
    out = ROOT / "results" / "main_table.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
