"""主结果表里"验证集选出的 C"那一行（10-13 补；CPU，几秒；只读 review_checks10.py 缓存的预测）。

论文的 TF-IDF + LR 基线用事先固定的 C = 4；验证集会选 C = 16（表 S38）。主表里原先看不到后者，
这里按主表的七列算出 C = 16 在时间划分"全部"和"非 derived"两个区块的结果；同时算 C = 4 作核对（应与主表一致）。
要先运行过 python src/review_checks10.py a（生成 results/tfidf_sensitivity/ 下的预测缓存）。
输出：results/review_checks/summary22.md
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import CUTOFF, M40, evaluate, load, source_type_map  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "results" / "tfidf_sensitivity"
OUT = ROOT / "results" / "review_checks" / "summary22.md"


def row(t, p):
    e = evaluate(t.reset_index(drop=True), p.reset_index(drop=True)[M40])
    v4 = float(np.mean([e["per_metric"][k]["macro_f1"] for k in ["AT", "UI", "SC", "SI", "SA"]]))
    return f"{e['mean_macro_f1']:.3f} | {v4:.3f} | {e['exact_match']:.3f} | {e['score_mae']:.3f} | {e['band_acc']:.3f} | {e['under_rate']:.3f} | {e['hc_recall']:.3f}"


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    nd = (test["label_type"] != "derived").to_numpy()
    lines = ["# TF-IDF + LR：固定的 C = 4 与验证集选出的 C = 16，主表七列（时间划分；自动生成）\n",
             "| C | 标签 | n | Macro-F1 | v4-F1 | Exact | MAE | Band | Under | H+C rec. |", "|---|---|---|---|---|---|---|---|---|---|"]
    for C in (4.0, 16.0):
        p = pd.read_parquet(CACHE / f"clf_C{C}_df2.parquet").set_index("cve_id").loc[test["cve_id"]].reset_index()
        lines.append(f"| {C:g} | 全部 | {len(test):,} | {row(test, p)} |")
        lines.append(f"| {C:g} | 非 derived | {int(nd.sum()):,} | {row(test[nd], p[nd])} |")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
