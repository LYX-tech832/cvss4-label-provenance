"""Paired bootstrap intervals for the LLM comparison (CPU): used for Table 4 (Section 7.5) and the discussion of conclusion validity in Section 8.2.

Sample: the same 2,000 test CVEs as in compare_llm_baseline.py (stratified by label type: derived 300, independent 700, v4_only 500,
other 500).
Methods: AutoCVSS + DeepSeek-V4-Pro (main run: default API temperature, DONT_KNOW -> most conservative, as in AutoCVSS),
AutoCVSS + Qwen3-8B, TF-IDF+LR (description + CWE), TF-IDF+LR (description only, the same input as the LLM), DeBERTa and
DeBERTa + v3.1 auxiliary task (configuration selected in W4, 5 seeds).
Resampling: with replacement within each label type (the count of each type unchanged, matching the stratified design), 1,000 times by
default; all methods use the same resampled CVEs (paired); methods with several seeds are averaged over seeds in each resample.
Intervals are 95% percentile intervals.
Scopes: whole sample, without derived, and the four label types. Metrics as in evaluate() (aggregate_seeds.fast_scores).
The sample is stratified by type, so the "whole sample" and "without derived" rows do not represent the distribution of the test set.
Output: results/autocvss_baseline/deepseek-v4-pro_DTD_s0/compare_bootstrap.md
"""

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import BOOT_KEYS, Encoded, fast_scores  # noqa: E402
from baselines_v0 import load, source_type_map  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
LLM = ROOT / "results" / "autocvss_baseline"
MAIN = LLM / "deepseek-v4-pro_DTD_s0"
TYPES = ["derived", "independent", "v4_only", "other"]
SCOPES = {"whole sample": TYPES, "without derived": TYPES[1:], **{t: [t] for t in TYPES}}
METHODS = {"DeepSeek": [MAIN / "predictions.parquet"],
           "Qwen3-8B": [LLM / "Qwen3-8B_DTD_s0" / "predictions.parquet"],
           "TF-IDF": [ROOT / "results" / "baselines_v0" / "predictions" / "T2_temporal_tfidf_lr.parquet"],
           "TF-IDF (description only)": [ROOT / "results" / "ablation_desc_only" / "T2_temporal_tfidf_lr_desc_only.parquet"],
           "DeBERTa": sorted(ENC.glob("T2_temporal_deberta-v3-base_none_e5_cwinv_sqrt_s[0-9]/pred_latent.parquet")),
           "DeBERTa+auxiliary": sorted(ENC.glob("T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s[0-9]/pred_latent.parquet"))}
CONTRASTS = [("DeepSeek", "TF-IDF"), ("DeepSeek", "TF-IDF (description only)"), ("DeBERTa+auxiliary", "DeepSeek"),
             ("DeBERTa+auxiliary", "TF-IDF"), ("DeepSeek", "Qwen3-8B")]
NAMES = {"mean_macro_f1": "Mean macro-F1", "band_acc": "Band accuracy", "under_rate": "Underestimation", "score_mae": "Score MAE"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--boot", type=int, default=1000, help="number of resamples")
    args = ap.parse_args()
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    ids = pd.read_parquet(MAIN / "predictions.parquet")["cve_id"]
    truth = df.set_index("cve_id").loc[ids].reset_index()
    t = Encoded(truth, "y_")
    enc = {name: [Encoded(pd.read_parquet(f).set_index("cve_id").loc[ids].reset_index()) for f in files]
           for name, files in METHODS.items()}
    lt = truth["label_type"].to_numpy()
    rng = np.random.default_rng(0)

    def score_all(idx):
        """Metrics of each method on these CVEs (averaged over seeds first when there are several)."""
        out = {}
        for name, ps in enc.items():
            rs = [fast_scores(t, p, idx) for p in ps]
            out[name] = {k: float(np.mean([r[k] for r in rs])) for k in BOOT_KEYS}
        return out

    lines = [f"# Paired bootstrap for the LLM comparison (the same {len(ids):,} test CVEs; {args.boot:,} resamples within label types; 95% percentile intervals; generated automatically)\n",
             "Seeds per method: " + ", ".join(f"{n} {len(ps)}" for n, ps in enc.items()) + ". "
             "The sample is stratified by label type, so \"whole sample\" and \"without derived\" do not represent the distribution of the test set.\n"]
    tab_m = ["\n## Point estimates and 95% intervals of each method\n", "| Scope | Method | " + " | ".join(NAMES[k] for k in BOOT_KEYS) + " |", "|---|---|" + "---|" * len(BOOT_KEYS)]
    tab_c = ["\n## Pairwise differences (A − B) and 95% intervals\n", "| Scope | A − B | " + " | ".join(NAMES[k] + " difference" for k in BOOT_KEYS) + " |", "|---|---|" + "---|" * len(BOOT_KEYS)]
    for scope, types in SCOPES.items():
        strata = [np.flatnonzero(lt == ty) for ty in types]
        n = sum(len(s) for s in strata)
        point = score_all(np.concatenate(strata))
        boots = [score_all(np.concatenate([rng.choice(s, size=len(s), replace=True) for s in strata])) for _ in range(args.boot)]
        for name in enc:
            ci = {k: np.percentile([b[name][k] for b in boots], [2.5, 97.5]) for k in BOOT_KEYS}
            tab_m.append(f"| {scope} (n={n:,}) | {name} | " + " | ".join(
                f"{point[name][k]:.3f} [{ci[k][0]:.3f}, {ci[k][1]:.3f}]" for k in BOOT_KEYS) + " |")
        for a, b in CONTRASTS:
            ci = {k: np.percentile([bb[a][k] - bb[b][k] for bb in boots], [2.5, 97.5]) for k in BOOT_KEYS}
            tab_c.append(f"| {scope} (n={n:,}) | {a} − {b} | " + " | ".join(
                f"{point[a][k] - point[b][k]:+.3f} [{ci[k][0]:+.3f}, {ci[k][1]:+.3f}]" for k in BOOT_KEYS) + " |")
    lines += tab_c + ["\nAn interval that excludes 0 indicates a stable difference in that scope. Lower underestimation rate and MAE are better."] + tab_m
    out = MAIN / "compare_bootstrap.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
