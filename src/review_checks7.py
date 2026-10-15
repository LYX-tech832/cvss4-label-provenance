"""Records with several vectors and seed uncertainty (CPU, a few minutes):

1. Records with several vectors: when the CNA container holds several v4.0 (or v3.1) vectors, the first one is used; how much do the
   results of the main methods on the temporal split test set, and VulDB's FD_oos, change when these records are excluded?
2. Seed uncertainty of the ten-epoch LOSO comparison: per-seed differences auxiliary 5 epochs − baseline 10 epochs, with t intervals
   (4 degrees of freedom).
Output: results/review_checks/summary7.md
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import CUTOFF, evaluate, load, source_type_map  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
OUT = ROOT / "results" / "review_checks" / "summary7.md"


def multi_vector_ids():
    raw = pd.read_parquet(ROOT / "data" / "processed" / "cve_records.parquet", columns=["cve_id", "cna_v40", "cna_v31"])
    n40 = raw["cna_v40"].map(len)
    n31 = raw["cna_v31"].map(len)
    return set(raw.loc[n40 > 1, "cve_id"]), set(raw.loc[(n40 >= 1) & (n31 > 1), "cve_id"])


def part1(lines):
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    multi40, multi31 = multi_vector_ids()
    multi = (multi40 | multi31) & set(df["cve_id"])
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    keep = ~test["cve_id"].isin(multi).to_numpy()
    lines += ["## 1. Records with several vectors\n",
              f"Records of the v4.0 dataset whose CNA gave several v4.0 vectors: {len(multi40 & set(df['cve_id'])):,}; "
              f"records with a v4.0 vector whose CNA gave several v3.1 vectors: {len(multi31 & set(df['cve_id'])):,}; together (deduplicated) {len(multi):,}; "
              f"of these, {int((~keep).sum()):,} are in the temporal split test set and {len(multi) - int((~keep).sum()):,} in the training and validation parts.\n",
              "Change of mean macro-F1 / band accuracy when these test CVEs are excluded (models not retrained; these records are used as usual in training):\n",
              "| Method | All: original → excluded | Non-derived: original → excluded |", "|---|---|---|"]
    runs = {"TF-IDF + LR": [ROOT / "results" / "baselines_v0" / "predictions" / "T2_temporal_tfidf_lr.parquet"],
            "DeBERTa (5 seeds)": [ENC / f"T2_temporal_deberta-v3-base_none_e5_cwinv_sqrt_s{s}" / "pred_latent.parquet" for s in range(5)],
            "DeBERTa + auxiliary task (5 seeds)": [ENC / f"T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s{s}" / "pred_latent.parquet" for s in range(5)]}
    nd = (test["label_type"] != "derived").to_numpy()
    for name, paths in runs.items():
        ps = [pd.read_parquet(p).set_index("cve_id").loc[test["cve_id"]].reset_index() for p in paths]
        cells = []
        for m in [np.ones(len(test), bool), nd]:
            a = [evaluate(test[m].reset_index(drop=True), p[m].reset_index(drop=True)) for p in ps]
            b = [evaluate(test[m & keep].reset_index(drop=True), p[m & keep].reset_index(drop=True)) for p in ps]
            f = lambda rs, k: np.mean([r[k] for r in rs])  # noqa: E731
            cells.append(f"{f(a, 'mean_macro_f1'):.3f} / {f(a, 'band_acc'):.3f} → {f(b, 'mean_macro_f1'):.3f} / {f(b, 'band_acc'):.3f}")
        lines.append(f"| {name} | {cells[0]} | {cells[1]} |")
    by_src = test.loc[~keep, "source"].value_counts().head(8)
    lines.append("\nSources of these records in the test set (top 8): " + "; ".join(f"{s} {n}" for s, n in by_src.items()) + "\n")


def part2(lines):
    lines += ["\n## 2. LOSO: per-seed differences auxiliary 5 epochs − baseline 10 epochs (mean macro-F1)\n",
              "| Held out | Per-seed differences (seeds 0–4) | Mean | t interval (4 degrees of freedom) | Positive seeds |", "|---|---|---|---|---|"]
    for sp in ["VulnCheck", "GitHub_M", "VulDB"]:
        f = lambda tag, s: json.loads((ENC / f"T2_loso-{sp}_deberta-v3-base_none{tag}_s{s}" / "results.json").read_text(encoding="utf-8"))["latent"]["mean_macro_f1"]  # noqa: E731
        d = np.array([f("_aux_e5_cwinv_sqrt", s) - f("_e10_cwinv_sqrt", s) for s in range(5)])
        h = stats.t.ppf(0.975, 4) * d.std(ddof=1) / np.sqrt(5)
        lines.append(f"| {sp} | {', '.join(f'{x:+.3f}' for x in d)} | {d.mean():+.3f} | [{d.mean() - h:+.3f}, {d.mean() + h:+.3f}] | {int((d > 0).sum())} |")


def main():
    lines = ["# Records with several vectors and seed uncertainty (generated automatically)\n"]
    part1(lines)
    part2(lines)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
