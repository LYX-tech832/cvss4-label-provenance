"""The model with 5% of the v4.0 training labels against the baseline encoder trained on all labels, with intervals
(CPU, about 3 minutes; reads only existing predictions).

Random 5% of the v4.0 training labels + v3.1 auxiliary task (seeds 0-2) against all labels, no auxiliary task, 25 epochs
(the baseline selected for Table 2, also seeds 0-2), on the temporal split test set; subsets: all, non-derived and R-inconsistent
labels (Section 7.3); paired bootstrap (test CVEs resampled 1,000 times, each variant averaged over its seeds), computed as the other
differences in the paper.
Output: results/review_checks/summary18.md
"""

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded  # noqa: E402
from baselines_v0 import CUTOFF, evaluate, load, source_type_map  # noqa: E402
from review_checks import clean_mask  # noqa: E402
from review_gpu2_summary import boot, read, runs  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "review_checks" / "summary18.md"


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    stem = "T2_temporal_deberta-v3-base_none"
    vers = {"5% + v3.1 auxiliary": runs(stem, "_aux_e5_cwinv_sqrt_frac0.05", range(3)),
            "all labels, baseline 25 epochs": runs(stem, "_e25_cwinv_sqrt", range(3))}
    assert all(len(p) == 3 for p in vers.values()), {k: len(v) for k, v in vers.items()}
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    test["clean"] = clean_mask(test)
    ids = test["cve_id"]
    t = Encoded(test, "y_")
    preds = {v: read(p, ids) for v, p in vers.items()}
    enc = {v: [Encoded(p) for p in ps] for v, ps in preds.items()}
    lines = ["# 5% of the labels + v3.1 auxiliary task against all labels, no auxiliary task, 25 epochs (temporal split, seeds 0–2; generated automatically)\n"]
    subsets = {"all": np.ones(len(test), bool), "non-derived": (test["label_type"] != "derived").to_numpy(),
               "R-inconsistent": test["clean"].to_numpy()}
    for name, m in subsets.items():
        idx = np.flatnonzero(m)
        tt = test.iloc[idx].reset_index(drop=True)
        lines += [f"\n## {name}: n = {len(idx):,}\n", "| Variant | Seeds | Mean macro-F1 (mean ± sd) | Band accuracy |", "|---|---|---|---|"]
        for v, ps in preds.items():
            rs = [evaluate(tt, p.iloc[idx].reset_index(drop=True)) for p in ps]
            mf = [r["mean_macro_f1"] for r in rs]
            lines.append(f"| {v} | {len(ps)} | {np.mean(mf):.3f} ± {np.std(mf, ddof=1):.3f} | {np.mean([r['band_acc'] for r in rs]):.3f} |")
        rng = np.random.default_rng(0)
        k, c0, c1 = boot(t, enc, "5% + v3.1 auxiliary", "all labels, baseline 25 epochs", idx, rng)
        lines += ["\n| A − B | Common seeds | Mean macro-F1 difference | Band accuracy difference |", "|---|---|---|---|",
                  f"| 5% + v3.1 auxiliary − all labels, baseline 25 epochs | {k} | {c0} | {c1} |"]
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
