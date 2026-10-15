"""Control: the supervised baseline without the CWE identifier, using the description only (CPU).

The input of the supervised methods is "description + CWE identifier" (the text column of baselines_v0.load()), whereas the AutoCVSS
LLM baseline reads only the description, as in its original setting. This script retrains the same TF-IDF+LR (same hyperparameters as
baselines_v0) on the description only, to quantify the difference that the CWE identifier makes.
Split: T2 temporal split (training before 2026, test in 2026).
Output: results/ablation_desc_only/ (prediction file + summary.md); compare_llm_baseline.py adds "TF-IDF+LR (description only)" automatically.
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
    print(f"training {len(train):,}, test {len(test):,}; share with a CWE identifier: training {train['has_cwe'].mean():.1%}, test {test['has_cwe'].mean():.1%}", flush=True)

    pred = pred_tfidf_lr(train, test, with_v31=False).reset_index(drop=True)
    OUT.mkdir(parents=True, exist_ok=True)
    pred.assign(cve_id=test["cve_id"].values, source=test["source"].values).to_parquet(OUT / "T2_temporal_tfidf_lr_desc_only.parquet", index=False)
    ref = pd.read_parquet(ROOT / "results/baselines_v0/predictions/T2_temporal_tfidf_lr.parquet").set_index("cve_id").loc[test["cve_id"]].reset_index()

    lines = ["# Control: TF-IDF+LR on the description only vs description + CWE identifier (T2 temporal split, generated automatically)\n",
             f"- Training {len(train):,} CVEs (before 2026), test {len(test):,} CVEs (2026); "
             f"share with a CWE identifier: training {train['has_cwe'].mean():.1%}, test {test['has_cwe'].mean():.1%}",
             "- Same hyperparameters as baselines_v0, only the input text differs; single run (logistic regression is deterministic)\n",
             "| Scope | Input | " + " | ".join(c for _, c in COLS) + " |", "|---|---|" + "---|" * len(COLS)]
    for scope in ["all test labels"] + TYPES + ["with CWE", "without CWE"]:
        m = {"all test labels": np.ones(len(test), bool), "with CWE": test["has_cwe"].values,
             "without CWE": ~test["has_cwe"].values}.get(scope, (test["label_type"] == scope).values)
        if m.sum() < 30:
            continue
        for name, p in [("description + CWE", ref), ("description only", pred)]:
            r = scores(test[m], p[m])
            lines.append(f"| {scope} (n={m.sum():,}) | {name} | " + " | ".join(f"{r[k]:.3f}" for k, _ in COLS) + " |")
    (OUT / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
