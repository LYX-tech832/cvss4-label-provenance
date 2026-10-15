"""Ranking of the methods with equal weight per source (CPU, about 3 minutes).

VulnCheck and GitHub account for 59.6% of the non-derived test labels of the temporal split, so the non-derived results are largely
the results of these two sources. This script checks whether the ranking of the classifiers and the pipelines also holds when every
source has equal weight (the source-macro averages of Table S31 do not include the pipelines): metrics are computed for each source
with at least 30 (or 100) test CVEs and averaged with equal weight; intervals of the differences come from resampling the sources
(2,000 times).
Output: results/review_checks/summary15.md
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded, fast_scores  # noqa: E402
from baselines_v0 import CUTOFF, load  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
BASE = ROOT / "results" / "baselines_v0" / "predictions"
PIPE = ROOT / "results" / "pipeline_baseline" / "predictions"
OUT = ROOT / "results" / "review_checks" / "summary15.md"
KEYS = ("mean_macro_f1", "band_acc", "under_rate")
REF = "pipeline (rule R)"
rng = np.random.default_rng(0)


def main():
    df = load()
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    ids = test["cve_id"]
    t = Encoded(test, "y_")

    def enc(path):
        return Encoded(pd.read_parquet(path).set_index("cve_id").loc[ids].reset_index())
    methods = {"TF-IDF + LR": [enc(BASE / "T2_temporal_tfidf_lr.parquet")],
               REF: [enc(PIPE / "T2_temporal_pipeline_rule_R.parquet")],
               "pipeline (SC/SI/SA = N)": [enc(PIPE / "T2_temporal_pipeline_scsisa_N.parquet")],
               "DeBERTa (25 epochs)": [enc(ENC / f"T2_temporal_deberta-v3-base_none_e25_cwinv_sqrt_s{s}" / "pred_latent.parquet") for s in range(5)],
               "DeBERTa + auxiliary": [enc(ENC / f"T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s{s}" / "pred_latent.parquet") for s in range(5)]}
    src = test["source"].to_numpy()
    counts = test["source"].value_counts()

    def score(m, idx):
        rs = [fast_scores(t, e, idx) for e in methods[m]]
        return {k: float(np.mean([r[k] for r in rs])) for k in KEYS}

    lines = ["# Ranking of the methods with equal weight per source (temporal split test set, generated automatically)\n",
             "## 0. For comparison: pooled over CVEs (as in Table 2 of the paper)\n", "| Scope | Method | Mean macro-F1 | Band accuracy | Underestimation |", "|---|---|---|---|---|"]
    for name, idx in [("all (21,900)", np.arange(len(test))), ("non-VulDB (16,749)", np.flatnonzero(src != "VulDB"))]:
        for m in methods:
            s = score(m, idx)
            lines.append(f"| {name} | {m} | " + " | ".join(f"{s[k]:.3f}" for k in KEYS) + " |")

    for min_n in (30, 100):
        keep_all = [s for s, n in counts.items() if n >= min_n]
        per = {m: {s: score(m, np.flatnonzero(src == s)) for s in keep_all} for m in methods}
        for label, keep in [("all sources", keep_all), ("without VulDB", [s for s in keep_all if s != "VulDB"])]:
            n_cve = int(sum(counts[s] for s in keep))
            lines += [f"\n## Sources with at least {min_n} test CVEs, {label}: {len(keep)} sources ({n_cve:,} CVEs), equal weight per source\n",
                      "| Method | Mean macro-F1 | Band accuracy | Underestimation |", "|---|---|---|---|"]
            for m in methods:
                lines.append(f"| {m} | " + " | ".join(f"{np.mean([per[m][s][k] for s in keep]):.3f}" for k in KEYS) + " |")
            lines += [f"\nDifference from {REF} (method − pipeline; interval: sources resampled 2,000 times)\n",
                      "| Method | Band accuracy difference | Sources where the method is higher | Mean macro-F1 difference | Sources where the method is higher |", "|---|---|---|---|---|"]
            for m in methods:
                if m == REF:
                    continue
                cells = []
                for k in ("band_acc", "mean_macro_f1"):
                    d = np.array([per[m][s][k] - per[REF][s][k] for s in keep])
                    bs = np.array([d[rng.integers(len(keep), size=len(keep))].mean() for _ in range(2000)])
                    cells += [f"{d.mean():+.3f} [{np.percentile(bs, 2.5):+.3f}, {np.percentile(bs, 97.5):+.3f}]", f"{int((d > 0).sum())} / {len(keep)}"]
                lines.append(f"| {m} | " + " | ".join(cells) + " |")
        if min_n == 100:
            lines += ["\n### Band accuracy of each source (at least 100 CVEs): TF-IDF + LR / pipeline (rule R) / DeBERTa + auxiliary\n", "| Source | n | TF-IDF + LR | pipeline (rule R) | DeBERTa + auxiliary |", "|---|---|---|---|---|"]
            for s in keep_all:
                lines.append(f"| {s} | {counts[s]:,} | {per['TF-IDF + LR'][s]['band_acc']:.3f} | {per[REF][s]['band_acc']:.3f} | {per['DeBERTa + auxiliary'][s]['band_acc']:.3f} |")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nwritten to {OUT}")


if __name__ == "__main__":
    main()
