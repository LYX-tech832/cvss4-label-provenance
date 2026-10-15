"""Summary of the additional GPU runs (CPU, a few minutes): the three experiments of scripts/run_review_gpu.sh, T2 temporal split, seeds 0-2.

1. Training epochs: baseline / v3.1 auxiliary task trained for 10 epochs vs 5 epochs (the same seeds as the W4 main runs); gain of the
   auxiliary task at 10 epochs; best epoch.
2. Pseudo-label control (pseudo): the same 60,000 auxiliary samples as the v3.1 auxiliary task, but with v4 pseudo-labels converted with
   rule R that supervise the v4 heads directly.
3. DeBERTa pipeline (v31only): trains only the v3.1 heads on these samples and converts with rule R; compared with the TF-IDF pipeline
   and the v3.1 auxiliary model.
Differences: paired bootstrap (test CVEs resampled 1,000 times, each variant averaged over its seeds), on all test labels and without
derived labels.
Output: results/review_gpu/summary.md
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import BOOT_KEYS, metrics, paired_bootstrap  # noqa: E402
from baselines_v0 import M40, evaluate, load, source_type_map  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
OUT = ROOT / "results" / "review_gpu"
SEEDS = [0, 1, 2]
STEM = "T2_temporal_deberta-v3-base_none"
VERSIONS = {
    "baseline (5 epochs)": "_e5_cwinv_sqrt", "v3.1 auxiliary (5 epochs)": "_aux_e5_cwinv_sqrt",
    "baseline (10 epochs)": "_e10_cwinv_sqrt", "v3.1 auxiliary (10 epochs)": "_aux_e10_cwinv_sqrt",
    "pseudo-labels (5 epochs)": "_pseudo_e5_cwinv_sqrt", "DeBERTa pipeline (5 epochs)": "_v31only_e5",
}
KEYS = ["mean_macro_f1", "exact_match", "score_mae", "band_acc", "under_rate", "hc_recall"]


def dirs(tag):
    return {s: ENC / f"{STEM}{tag}_s{s}" for s in SEEDS if (ENC / f"{STEM}{tag}_s{s}" / "pred_latent.parquet").exists()}


def per_metric(d, df, mask_nd):
    p = pd.read_parquet(d / "pred_latent.parquet")
    t = df.set_index("cve_id").loc[p["cve_id"]].reset_index()
    out = {}
    for scope, m in [("all", np.ones(len(t), bool)), ("non_derived", (t["label_type"] != "derived").to_numpy())]:
        r = evaluate(t[m].reset_index(drop=True), p[m].reset_index(drop=True))
        out[scope] = {k: r["per_metric"][k]["macro_f1"] for k in M40}
    return out


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    runs = {v: dirs(tag) for v, tag in VERSIONS.items()}
    lines = ["# Additional GPU runs: ten-epoch training, pseudo-labels and pipeline (T2 temporal split, seeds 0–2; generated automatically)\n",
             "Completed runs: " + "; ".join(f"{v} {len(r)}/3" for v, r in runs.items()) + "\n"]
    have = {v: r for v, r in runs.items() if r}

    for scope, name in [("all", "all test labels (21,900)"), ("non_derived", "without derived labels (16,749)")]:
        lines += [f"\n## Mean ± standard deviation of each variant: {name}\n", "| Variant | Seeds | " + " | ".join(KEYS) + " | Best epoch |", "|---|---|" + "---|" * (len(KEYS) + 1)]
        for v, r in have.items():
            ms = [metrics(d, df)[scope] for d in r.values()]
            best = [json.loads((d / "results.json").read_text(encoding="utf-8"))["best_epoch"] + 1 for d in r.values()]
            n_ep = len(json.loads((next(iter(r.values())) / "results.json").read_text(encoding="utf-8"))["val_log"])
            lines.append(f"| {v} | {len(ms)} | " + " | ".join(f"{np.mean([m[k] for m in ms]):.3f} ± {np.std([m[k] for m in ms], ddof=1) if len(ms) > 1 else 0:.3f}" for k in KEYS)
                         + f" | {', '.join(map(str, best))} / {n_ep} |")

    pairs = [("v3.1 auxiliary (10 epochs)", "baseline (10 epochs)"), ("v3.1 auxiliary (5 epochs)", "baseline (5 epochs)"),
             ("baseline (10 epochs)", "baseline (5 epochs)"), ("v3.1 auxiliary (10 epochs)", "v3.1 auxiliary (5 epochs)"),
             ("pseudo-labels (5 epochs)", "baseline (5 epochs)"), ("v3.1 auxiliary (5 epochs)", "pseudo-labels (5 epochs)"),
             ("DeBERTa pipeline (5 epochs)", "baseline (5 epochs)"), ("v3.1 auxiliary (5 epochs)", "DeBERTa pipeline (5 epochs)")]
    lines += ["\n## Paired bootstrap: A − B (each averaged over seeds 0–2; 95% interval)\n",
              "| A − B | Scope | Mean macro-F1 difference | Band accuracy difference | Underestimation difference | Score MAE difference |", "|---|---|---|---|---|---|"]
    for a, b in pairs:
        if a in have and b in have:
            res = paired_bootstrap(df, have[b], have[a])
            for scope in ["all", "non_derived"]:
                r = res[scope]
                lines.append(f"| {a} − {b} | {'all' if scope == 'all' else 'without derived'} | " +
                             " | ".join(f"{r[k][0]:+.3f} [{r[k][1]:+.3f}, {r[k][2]:+.3f}]" for k in BOOT_KEYS) + " |")

    lines += ["\n## Per-metric macro-F1 (all test labels / without derived; mean over seeds)\n", "| Variant | " + " | ".join(M40) + " |", "|---|" + "---|" * len(M40)]
    for v, r in have.items():
        pm = [per_metric(d, df, None) for d in r.values()]
        lines.append(f"| {v} | " + " | ".join(f"{np.mean([x['all'][k] for x in pm]):.3f} / {np.mean([x['non_derived'][k] for x in pm]):.3f}" for k in M40) + " |")

    pl = json.loads((ROOT / "results" / "pipeline_baseline" / "metrics.json").read_text(encoding="utf-8"))["temporal"]["rule_R"]
    lines += ["\n## Reference: TF-IDF pipeline (rule R; results/pipeline_baseline)\n",
              "| Scope | Mean macro-F1 | Exact | MAE | Band accuracy | Underestimation | H+C recall |", "|---|---|---|---|---|---|---|"]
    for scope in ["all", "non_derived"]:
        x = pl[scope]
        lines.append(f"| {scope} | {x['mean_macro_f1']:.3f} | {x['exact_match']:.3f} | {x['score_mae']:.3f} | {x['band_acc']:.3f} | {x['under_rate']:.3f} | {x['hc_recall']:.3f} |")

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
