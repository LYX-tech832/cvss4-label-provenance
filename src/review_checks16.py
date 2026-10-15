"""Rows of the main results table for the C selected on validation data (CPU, seconds; reads only the predictions cached by review_checks10.py).

The TF-IDF + LR baseline of the paper uses a fixed C = 4; validation data would select C = 16 (Table S38). This script computes
the seven columns of the main table for C = 16 on the "all" and "non-derived" blocks of the temporal split, and for C = 4 as a check
(it should match the main table).
Run python src/review_checks10.py a first (it writes the cached predictions under results/tfidf_sensitivity/).
Output: results/review_checks/summary22.md
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
    lines = ["# TF-IDF + LR: fixed C = 4 and C = 16 selected on validation data, seven columns of the main table (temporal split; generated automatically)\n",
             "| C | Labels | n | Macro-F1 | v4-F1 | Exact | MAE | Band | Under | H+C rec. |", "|---|---|---|---|---|---|---|---|---|---|"]
    for C in (4.0, 16.0):
        p = pd.read_parquet(CACHE / f"clf_C{C}_df2.parquet").set_index("cve_id").loc[test["cve_id"]].reset_index()
        lines.append(f"| {C:g} | all | {len(test):,} | {row(test, p)} |")
        lines.append(f"| {C:g} | non-derived | {int(nd.sum()):,} | {row(test[nd], p[nd])} |")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
