"""Confidence intervals of the ranking reversal that include the LLM's sampling randomness (CPU, about 2 minutes).

DeepSeek-V4-Pro was run three times on the same 2,000 test CVEs with the settings of the main run (default sampling of the API):
the main run (26 September 2026) and two complete repetitions (scripts/run_llm_fullreps.py, 3 October 2026). Comparison: TF-IDF + LR
(description + CWE).
1. The difference "DeepSeek − TF-IDF" of each run (mean macro-F1, band accuracy) and its standard deviation over the three runs;
2. the difference averaged over the three runs, with two kinds of interval: resampling only the test CVEs (within label types, the three
   runs fixed), and two-level resampling (test CVEs within label types + the three runs with replacement), which includes the sampling
   randomness;
3. agreement between runs on the severity band and on the complete vector.
Output: results/autocvss_baseline/reversal_runs.md
"""

import sys
from itertools import combinations
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded, fast_scores  # noqa: E402
from baselines_v0 import M40, load, source_type_map  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
LLM = ROOT / "results" / "autocvss_baseline"
RUNS = {"main run (26 Sep)": "deepseek-v4-pro_DTD_s0", "full repetition 1 (3 Oct)": "deepseek-v4-pro_DTD_s0_fullrep1", "full repetition 2 (3 Oct)": "deepseek-v4-pro_DTD_s0_fullrep2"}
TYPES = ["derived", "independent", "v4_only", "other"]
SCOPES = {"whole sample": TYPES, "without derived labels": TYPES[1:]}
B = 2000


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    ids = pd.read_parquet(LLM / RUNS["main run (26 Sep)"] / "predictions.parquet")["cve_id"]
    truth = df.set_index("cve_id").loc[ids].reset_index()
    t = Encoded(truth, "y_")
    preds = {n: pd.read_parquet(LLM / d / "predictions.parquet").set_index("cve_id").loc[ids].reset_index() for n, d in RUNS.items()}
    runs = [Encoded(p) for p in preds.values()]
    tf = Encoded(pd.read_parquet(ROOT / "results" / "baselines_v0" / "predictions" / "T2_temporal_tfidf_lr.parquet").set_index("cve_id").loc[ids].reset_index())
    lt = truth["label_type"].to_numpy()
    rng = np.random.default_rng(0)
    lines = [f"# Ranking reversal and the LLM's sampling randomness (the same {len(ids):,} test CVEs, three runs of DeepSeek-V4-Pro; generated automatically)\n"]

    def diff(idx, which):
        a = [fast_scores(t, runs[i], idx) for i in which]
        b = fast_scores(t, tf, idx)
        return (np.mean([x["mean_macro_f1"] for x in a]) - b["mean_macro_f1"], np.mean([x["band_acc"] for x in a]) - b["band_acc"])

    for scope, types in SCOPES.items():
        strata = [np.flatnonzero(lt == ty) for ty in types]
        idx = np.concatenate(strata)
        per = np.array([diff(idx, [i]) for i in range(3)])
        lines += [f"\n## {scope} (n = {len(idx):,}): DeepSeek − TF-IDF\n", "| Run | Mean macro-F1 difference | Band accuracy difference |", "|---|---|---|"]
        for (name, _), d in zip(RUNS.items(), per):
            lines.append(f"| {name} | {d[0]:+.3f} | {d[1]:+.3f} |")
        lines.append(f"| Standard deviation over the three runs | {per[:, 0].std(ddof=1):.4f} | {per[:, 1].std(ddof=1):.4f} |")
        pt = diff(idx, [0, 1, 2])
        b1 = np.array([diff(np.concatenate([rng.choice(s, size=len(s), replace=True) for s in strata]), [0, 1, 2]) for _ in range(B)])
        b2 = np.array([diff(np.concatenate([rng.choice(s, size=len(s), replace=True) for s in strata]), list(rng.integers(0, 3, size=3))) for _ in range(B)])
        b0 = np.array([diff(np.concatenate([rng.choice(s, size=len(s), replace=True) for s in strata]), [0]) for _ in range(B)])
        ci = lambda x, j: f"[{np.percentile(x[:, j], 2.5):+.3f}, {np.percentile(x[:, j], 97.5):+.3f}]"  # noqa: E731
        lines += ["", "| Estimate | Mean macro-F1 difference | Band accuracy difference |", "|---|---|---|",
                  f"| Main run only, CVEs resampled | {per[0, 0]:+.3f} {ci(b0, 0)} | {per[0, 1]:+.3f} {ci(b0, 1)} |",
                  f"| Mean of the three runs, CVEs resampled | {pt[0]:+.3f} {ci(b1, 0)} | {pt[1]:+.3f} {ci(b1, 1)} |",
                  f"| Mean of the three runs, CVEs and runs resampled (two levels) | {pt[0]:+.3f} {ci(b2, 0)} | {pt[1]:+.3f} {ci(b2, 1)} |"]

    lines += ["\n## Agreement between runs (all 2,000 CVEs)\n", "| Pair of runs | Same severity band | Same complete vector |", "|---|---|---|"]
    names = list(RUNS)
    for i, j in combinations(range(3), 2):
        band = (runs[i].band == runs[j].band).mean()
        vec = np.all([preds[names[i]][k].to_numpy() == preds[names[j]][k].to_numpy() for k in M40], axis=0).mean()
        lines.append(f"| {names[i]} / {names[j]} | {band:.1%} | {vec:.1%} |")
    out = LLM / "reversal_runs.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
