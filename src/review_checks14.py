"""Gain of the auxiliary-task model over the selected baseline encoder on subsets (CPU, a few minutes; reads only stored predictions).

Differences between the auxiliary-task model (5 epochs, five seeds) and the baseline encoder selected for Table 2 (25 epochs, five seeds)
on all test labels, on the non-derived labels, on the R-inconsistent subset and on the test labels without a v3.1 vector from the same
source (Section 7.2). Temporal split test set; paired bootstrap (test CVEs resampled 1,000 times, each variant averaged over its seeds),
as in review_gpu2_summary.py.
Output: results/review_checks/summary20.md
"""

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded  # noqa: E402
from baselines_v0 import CUTOFF, load, source_type_map  # noqa: E402
from review_checks import clean_mask  # noqa: E402
from review_gpu2_summary import boot, read, runs  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "review_checks" / "summary20.md"


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    test["clean"] = clean_mask(test)
    stem = "T2_temporal_deberta-v3-base_none"
    vers = {"aux5": "_aux_e5_cwinv_sqrt", "none25": "_e25_cwinv_sqrt"}
    t = Encoded(test, "y_")
    enc = {v: [Encoded(p) for p in read(runs(stem, tag, range(5)), test["cve_id"])] for v, tag in vers.items()}
    subsets = {"all": np.ones(len(test), bool), "non-derived": (test["label_type"] != "derived").to_numpy(),
               "R-inconsistent": test["clean"].to_numpy(), "no same-source v3.1": (~test["has_v31"]).to_numpy()}
    lines = ["# Auxiliary-task model (5 epochs) − baseline encoder (25 epochs, selected for Table 2), by subset (generated automatically)\n",
             f"Seeds: auxiliary {len(enc['aux5'])}, baseline {len(enc['none25'])}. Paired bootstrap, test CVEs resampled 1,000 times.\n",
             "| Subset | n | Mean macro-F1 difference | Band accuracy difference |", "|---|---|---|---|"]
    for name, m in subsets.items():
        idx = np.flatnonzero(m)
        k, f1, band = boot(t, enc, "aux5", "none25", idx, np.random.default_rng(0))
        lines.append(f"| {name} | {len(idx):,} | {f1} | {band} |")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
