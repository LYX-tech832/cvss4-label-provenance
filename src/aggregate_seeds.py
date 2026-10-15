"""Multi-seed summary and paired comparison (CPU): with and without the v3.1 auxiliary task.

Reads all T2 runs in results/encoder/ (run names as in train_encoder.py) and pairs them by (split, configuration, seed):
  configuration = the hyperparameters other than the auxiliary task (epochs, class weighting); the λ of the auxiliary variant is recorded
  as part of its configuration.
Metrics are recomputed from pred_latent.parquet on two scopes: all test labels, and without derived labels (VulDB etc.).
Statistics (as in Section 5.5 of the paper):
  - mean ± standard deviation per (split, variant);
  - **main test: paired bootstrap within each split**: the split's test CVEs are resampled with replacement 1,000 times; in each resample
    the metrics of every seed of both variants are computed and averaged over seeds, and the difference (auxiliary − baseline) is taken;
    the 95% percentile interval is reported. No test pools the splits (their test sets differ); no rank test over the 5 seeds
    (with n = 5 the smallest two-sided Wilcoxon p-value is 0.0625);
  - descriptive summary: over all (split, seed) pairs, the number of pairs with a difference > 0.
Output: results/encoder/aggregate_seeds.md
Usage: python src/aggregate_seeds.py [--config_none e5_cwinv_sqrt] [--config_aux e5] [--lam 1]
(the two variants can each use the best configuration selected on the validation set)
"""

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import M40, SEVERITY_ORDER, evaluate, load, source_type_map, to_vector, v4_score  # noqa: E402
from cvss_utils import V40_METRICS  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
NAME = re.compile(r"^T2_(?P<split>.+?)_deberta-v3-base_none(?P<aux>_aux)?(?:_lam(?P<lam>[0-9.]+))?(?P<cfg>(?:_e\d+)?(?:_cw\w+?)?)_s(?P<seed>\d+)$")
KEYS = ["mean_macro_f1", "exact_match", "score_mae", "band_acc", "under_rate", "hc_recall"]


def metrics(run_dir, df):
    p = pd.read_parquet(run_dir / "pred_latent.parquet")
    t = df.set_index("cve_id").loc[p["cve_id"]].reset_index()
    out = {}
    for scope, m in [("all", np.ones(len(t), bool)), ("non_derived", (t["label_type"] != "derived").values)]:
        if m.sum() >= 30:
            r = evaluate(t[m].reset_index(drop=True), p[m].reset_index(drop=True))
            out[scope] = {k: r[k] for k in KEYS}
    return out


class Encoded:
    """Encode a set of predictions (or true labels) as arrays for fast resampling: integer codes of each metric, CVSS-B score, band index."""

    def __init__(self, frame, prefix=""):
        self.codes = {k: frame[prefix + k].map({v: i for i, v in enumerate(V40_METRICS[k])}).to_numpy() for k in M40}
        vecs = frame[[prefix + k for k in M40]].set_axis(M40, axis=1).apply(to_vector, axis=1)
        sc = [v4_score(v) for v in vecs]
        self.score = np.array([s for s, _ in sc], dtype=float)
        self.band = np.array([SEVERITY_ORDER.get(b, -1) for _, b in sc])


def fast_scores(t, p, idx):
    """Same definitions as evaluate() (macro-F1 over the full label set, classes that do not occur score 0), but only the quantities needed for resampling, much faster."""
    f1s = []
    for k in M40:
        n_cls = len(V40_METRICS[k])
        cm = np.bincount(t.codes[k][idx] * n_cls + p.codes[k][idx], minlength=n_cls * n_cls).reshape(n_cls, n_cls)
        tp = np.diag(cm)
        denom = 2 * tp + (cm.sum(0) - tp) + (cm.sum(1) - tp)
        f1s.append(np.where(denom > 0, 2 * tp / np.maximum(denom, 1), 0.0).mean())
    tb, pb = t.band[idx], p.band[idx]
    return {"mean_macro_f1": float(np.mean(f1s)), "band_acc": float((tb == pb).mean()), "under_rate": float((pb < tb).mean()),
            "score_mae": float(np.nanmean(np.abs(t.score[idx] - p.score[idx])))}


BOOT_KEYS = ["mean_macro_f1", "band_acc", "under_rate", "score_mae"]


def paired_bootstrap(df, dirs_none, dirs_aux, B=1000, seed=0):
    """Within one split: difference between two variants (several seeds each) on the same test CVEs (auxiliary − baseline) and its 95% percentile interval."""
    ids = pd.read_parquet(next(iter(dirs_none.values())) / "pred_latent.parquet")["cve_id"]
    truth = df.set_index("cve_id").loc[ids].reset_index()
    t = Encoded(truth, "y_")
    enc = {v: [Encoded(pd.read_parquet(d / "pred_latent.parquet").set_index("cve_id").loc[ids].reset_index())
               for d in dirs.values()] for v, dirs in [("none", dirs_none), ("aux", dirs_aux)]}
    rng = np.random.default_rng(seed)
    out = {}
    for scope, mask in [("all", np.ones(len(truth), bool)), ("non_derived", (truth["label_type"] != "derived").to_numpy())]:
        pool = np.flatnonzero(mask)
        if len(pool) < 30:
            continue

        def diff(idx):
            per_run = {v: [fast_scores(t, p, idx) for p in enc[v]] for v in enc}
            avg = {v: {k: np.mean([r[k] for r in rs]) for k in BOOT_KEYS} for v, rs in per_run.items()}
            return {k: avg["aux"][k] - avg["none"][k] for k in BOOT_KEYS}

        point = diff(pool)
        boots = [diff(rng.choice(pool, size=len(pool), replace=True)) for _ in range(B)]
        out[scope] = {k: (point[k], *np.percentile([b[k] for b in boots], [2.5, 97.5])) for k in BOOT_KEYS} | {"n": len(pool)}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config_none", default="", help="configuration suffix of the baseline variant, e.g. e5_cwinv_sqrt; empty string = default configuration")
    ap.add_argument("--config_aux", default="", help="configuration suffix of the auxiliary variant (without λ)")
    ap.add_argument("--lam", default="0.5", help="λ of the auxiliary variant, e.g. 0.5 or 1")
    ap.add_argument("--boot", type=int, default=1000, help="number of resamples of the paired bootstrap (0 = none)")
    args = ap.parse_args()
    cfg = {"none": ("_" + args.config_none) if args.config_none else "", "aux": ("_" + args.config_aux) if args.config_aux else ""}
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")

    runs = defaultdict(dict)  # (split, version) -> {seed: metrics}
    dirs = defaultdict(dict)  # (split, version) -> {seed: 运行目录}
    for d in sorted(ENC.iterdir()):
        m = NAME.match(d.name)
        if not m or not (d / "pred_latent.parquet").exists():
            continue
        ver = "aux" if m["aux"] else "none"
        if m["cfg"] != cfg[ver] or (ver == "aux" and float(m["lam"] or 0.5) != float(args.lam)):
            continue
        runs[(m["split"], ver)][int(m["seed"])] = metrics(d, df)
        dirs[(m["split"], ver)][int(m["seed"])] = d

    lines = [f"# Multi-seed summary (baseline configuration '{args.config_none or 'default'}'; auxiliary configuration '{args.config_aux or 'default'}', λ = {args.lam})\n"]
    for scope in ["all", "non_derived"]:
        lines += [f"\n## Scope: {'all test labels' if scope == 'all' else 'without derived labels'}\n",
                  "| Split | Variant | Seeds | " + " | ".join(KEYS) + " |", "|---" * (3 + len(KEYS)) + "|"]
        for (split, ver), seeds in sorted(runs.items()):
            vals = {k: [s[scope][k] for s in seeds.values() if scope in s] for k in KEYS}
            if not vals["mean_macro_f1"]:
                continue  # 该口径下没有样本（例如留一 VulDB 时测试集全是 derived）
            lines.append(f"| {split} | {ver} | {len(vals['mean_macro_f1'])} | " + " | ".join(f"{np.mean(v):.3f}±{np.std(v, ddof=1) if len(v) > 1 else 0:.3f}" for v in vals.values()) + " |")
        # 配对差值与 Wilcoxon 检验
        diffs = defaultdict(list)
        per_split = defaultdict(lambda: defaultdict(list))
        for (split, ver), seeds in runs.items():
            if ver != "aux" or (split, "none") not in runs:
                continue
            for seed, a in seeds.items():
                b = runs[(split, "none")].get(seed)
                if b and scope in a and scope in b:
                    for k in KEYS:
                        diffs[k].append(a[scope][k] - b[scope][k])
                        per_split[split][k].append(a[scope][k] - b[scope][k])
        n = len(diffs["mean_macro_f1"])
        lines += [f"\nDescriptive summary: differences (auxiliary − baseline) over all (split, seed) pairs, {n} pairs (no significance test, see Section 5.5):",
                  "| Metric | Mean difference | Pairs with difference > 0 |", "|---|---|---|"]
        for k in KEYS:
            d = np.array(diffs[k])
            lines.append(f"| {k} | {d.mean():+.4f} | {(d > 0).sum()}/{n} |" if n else f"| {k} | - | - |")
        if not n:
            continue
        lines.append("\nMean difference per split (mean F1 / band accuracy / underestimation rate): " + "; ".join(
            f"{s}: {np.mean(v['mean_macro_f1']):+.3f} / {np.mean(v['band_acc']):+.3f} / {np.mean(v['under_rate']):+.3f} ({len(v['mean_macro_f1'])} pairs)"
            for s, v in sorted(per_split.items())))

    # 主检验：各划分内的配对 bootstrap（论文第 5.5 节）
    if args.boot > 0:
        lines += [f"\n## Paired bootstrap within each split (auxiliary − baseline; averaged over seeds first; {args.boot} resamples; 95% percentile interval)\n",
                  "| Split | Scope | n | Seeds (baseline/aux) | Mean macro-F1 difference | Band accuracy difference | Underestimation difference | Score MAE difference |", "|---|---|---|---|---|---|---|---|"]
        for split in sorted({s for s, _ in dirs}):
            if (split, "none") not in dirs or (split, "aux") not in dirs:
                continue
            res = paired_bootstrap(df, dirs[(split, "none")], dirs[(split, "aux")], B=args.boot)
            for scope, r in res.items():
                cells = " | ".join(f"{r[k][0]:+.3f} [{r[k][1]:+.3f}, {r[k][2]:+.3f}]" for k in BOOT_KEYS)
                lines.append(f"| {split} | {'all' if scope == 'all' else 'without derived'} | {r['n']:,} | "
                             f"{len(dirs[(split, 'none')])}/{len(dirs[(split, 'aux')])} | {cells} |")
        lines.append("\nAn interval that excludes 0 indicates a stable difference on that split. Lower underestimation rate and MAE are better, so a negative difference in these two columns is an improvement.")
    out = ENC / "aggregate_seeds.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
