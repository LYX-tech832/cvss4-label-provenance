"""Summary of the GPU runs for configuration selection, step-matched baselines and timing sensitivity (scripts/run_review_gpu4.sh;
CPU, about 20 minutes).

1. Configuration selection: each split uses the configuration selected on its own validation set (src/select_loso_config.py).
2. Main comparison: the selected auxiliary configuration vs the selected baseline configuration of each split, seeds 0-4: the metrics of
   Table 2 (mean ± standard deviation), paired bootstrap of mean macro-F1 and band accuracy (test CVEs, models fixed), per-seed
   differences and t intervals (training randomness).
3. Step-matched baselines on the temporal split: auxiliary 5 epochs vs baseline 25 epochs (as many optimisation steps as auxiliary
   5 epochs) and 10 epochs.
4. Timing sensitivity: baseline 10 epochs and auxiliary 5 epochs (seeds 0-2), with and without the CVEs whose containers were updated
   after the cut-off (--exclude_ids).
Output: results/review_gpu/summary4.md
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import paired_bootstrap  # noqa: E402
from baselines_v0 import evaluate, load, source_type_map  # noqa: E402
from select_loso_config import select  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
OUT = ROOT / "results" / "review_gpu" / "summary4.md"
SPLITS = ["temporal", "loso:VulnCheck", "loso:GitHub_M", "loso:VulDB"]
COLS = [("mean_macro_f1", "Macro-F1"), ("v4_specific_f1", "v4-F1"), ("exact_match", "Exact"), ("score_mae", "MAE"),
        ("band_acc", "Band"), ("under_rate", "Under"), ("hc_recall", "H+C rec.")]
V4_SPECIFIC = ["AT", "UI", "SC", "SI", "SA"]


def run_dirs(split, tag, seeds=range(5)):
    return {s: ENC / f"T2_{split.replace(':', '-')}_deberta-v3-base_none{tag}_s{s}" for s in seeds
            if (ENC / f"T2_{split.replace(':', '-')}_deberta-v3-base_none{tag}_s{s}" / "pred_latent.parquet").exists()}


def tag_of(args):
    """Argument string of select_loso_config -> suffix of the run name."""
    a = args.split()
    lam = a[a.index("--aux_lambda") + 1] if "--aux_lambda" in a else None
    tag = "_aux" if "--aux_v31" in a else ""
    if lam and float(lam) != 0.5:
        tag += f"_lam{float(lam):g}"
    tag += f"_e{a[a.index('--epochs') + 1]}"
    if a[a.index("--class_weight") + 1] != "none":
        tag += f"_cw{a[a.index('--class_weight') + 1]}"
    return tag


def run_metrics(d, df, scope):
    p = pd.read_parquet(d / "pred_latent.parquet")
    t = df.set_index("cve_id").loc[p["cve_id"]].reset_index()
    m = np.ones(len(t), bool) if scope == "all" else (t["label_type"] != "derived").to_numpy()
    t, p = t[m].reset_index(drop=True), p[m].reset_index(drop=True)
    r = evaluate(t, p)
    r["v4_specific_f1"] = float(np.mean([r["per_metric"][k]["macro_f1"] for k in V4_SPECIFIC]))
    return r


def describe(dirs, df, scope):
    rs = [run_metrics(d, df, scope) for d in dirs.values()]
    return {k: (np.mean([r[k] for r in rs]), np.std([r[k] for r in rs], ddof=1) if len(rs) > 1 else float("nan")) for k, _ in COLS}


def per_seed(dirs_a, dirs_b, df, scope, key="mean_macro_f1"):
    common = sorted(set(dirs_a) & set(dirs_b))
    d = np.array([run_metrics(dirs_a[s], df, scope)[key] - run_metrics(dirs_b[s], df, scope)[key] for s in common])
    if len(d) < 2:
        return d, (float("nan"), float("nan"))
    h = stats.t.ppf(0.975, len(d) - 1) * d.std(ddof=1) / np.sqrt(len(d))
    return d, (d.mean() - h, d.mean() + h)


def compare(lines, df, title, dirs_aux, dirs_none, scopes):
    common = sorted(set(dirs_aux) & set(dirs_none))
    a = {s: dirs_aux[s] for s in common}
    b = {s: dirs_none[s] for s in common}
    boot = paired_bootstrap(df, b, a)
    lines += [f"\n{title} (common seeds {common})\n", "| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |",
              "|---|---|---|---|---|---|"]
    for scope in scopes:
        if scope not in boot:
            continue
        f, ba = boot[scope]["mean_macro_f1"], boot[scope]["band_acc"]
        d, ci = per_seed(a, b, df, scope)
        lines.append(f"| {scope} | {f[0]:+.3f} [{f[1]:+.3f}, {f[2]:+.3f}] | {ba[0]:+.3f} [{ba[1]:+.3f}, {ba[2]:+.3f}] | "
                     f"{', '.join(f'{x:+.3f}' for x in d)} | [{ci[0]:+.3f}, {ci[1]:+.3f}] | {int((d > 0).sum())}/{len(d)} |")


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    sel = select()
    lines = ["# Configuration selection, step-matched baselines and timing sensitivity (GPU runs; generated automatically)\n", "## 1. Configuration selected on each split's own validation set (seed 0)\n",
             "| Split | Auxiliary model | Baseline |", "|---|---|---|"]
    chosen = {}
    for sp in SPLITS:
        ta, tn = tag_of(sel[sp]["aux"]["args"]), tag_of(sel[sp]["none"]["args"])
        chosen[sp] = (ta, tn)
        lines.append(f"| {sp} | `{ta}` ({sel[sp]['aux']['scores'][sel[sp]['aux']['best']]:.4f}) | `{tn}` ({sel[sp]['none']['scores'][sel[sp]['none']['best']]:.4f}) |")

    lines.append("\n## 2. Main results of the selected configurations (as in Table 2; mean ± standard deviation, seeds 0–4)\n")
    for sp in SPLITS:
        ta, tn = chosen[sp]
        da, dn = run_dirs(sp, ta), run_dirs(sp, tn)
        scopes = ["all", "non_derived"] if sp == "temporal" else ["all"]
        for scope in scopes:
            lines += [f"\n### {sp}, {scope}\n", "| Model | Seeds | " + " | ".join(c for _, c in COLS) + " |", "|---" * (len(COLS) + 2) + "|"]
            for name, dd in [(f"baseline `{tn}`", dn), (f"auxiliary `{ta}`", da)]:
                if dd:
                    m = describe(dd, df, scope)
                    lines.append(f"| {name} | {len(dd)} | " + " | ".join(f"{m[k][0]:.3f} ± {m[k][1]:.3f}" for k, _ in COLS) + " |")
        compare(lines, df, f"{sp}: auxiliary − baseline (selected configurations)", da, dn, scopes)
        if sp != "temporal" and (ta != "_aux_e5_cwinv_sqrt" or tn != "_e5_cwinv_sqrt"):
            old_a, old_n = run_dirs(sp, "_aux_e5_cwinv_sqrt"), run_dirs(sp, "_e5_cwinv_sqrt")
            compare(lines, df, f"{sp}: reference, configuration selected on the temporal split, auxiliary − baseline", old_a, old_n, ["all"])

    lines.append("\n## 3. Temporal split: auxiliary 5 epochs vs baselines trained for different lengths\n")
    aux = run_dirs("temporal", "_aux_e5_cwinv_sqrt")
    for tn, label in [("_e5_cwinv_sqrt", "5 epochs"), ("_e10_cwinv_sqrt", "10 epochs"), ("_e25_cwinv_sqrt", "25 epochs (as many optimisation steps as auxiliary 5 epochs)")]:
        dn = run_dirs("temporal", tn)
        best = [json.loads((d / "results.json").read_text(encoding="utf-8"))["best_epoch"] + 1 for d in dn.values()]
        lines.append(f"\nBaseline {label}: best epoch {best}")
        compare(lines, df, f"auxiliary 5 epochs − baseline {label}", aux, dn, ["all", "non_derived"])

    lines.append("\n## 4. Timing sensitivity: without the CVEs whose containers were updated after the cut-off (seeds 0–2)\n")
    ex = json.loads((ROOT / "data" / "processed" / "late_updated_ids.json").read_text(encoding="utf-8"))
    lines.append(f"Removed: {len(ex['v4']):,} v4 training/validation samples and {len(ex['pool']):,} samples of the auxiliary pool; the test set is unchanged.\n")
    lines += ["| Model | Scope | All data | Without them |", "|---|---|---|---|"]
    pairs = {"baseline 10 epochs": ("_e10_cwinv_sqrt", "_e10_cwinv_sqrt_xlate"), "auxiliary 5 epochs": ("_aux_e5_cwinv_sqrt", "_aux_e5_cwinv_sqrt_xlate")}
    for name, (full, excl) in pairs.items():
        for scope in ["all", "non_derived"]:
            mf = describe(run_dirs("temporal", full, range(3)), df, scope)
            mx = describe(run_dirs("temporal", excl, range(3)), df, scope)
            lines.append(f"| {name} | {scope} | {mf['mean_macro_f1'][0]:.3f} / {mf['band_acc'][0]:.3f} | {mx['mean_macro_f1'][0]:.3f} / {mx['band_acc'][0]:.3f} |")
    compare(lines, df, "without them: auxiliary 5 epochs − baseline 10 epochs", run_dirs("temporal", "_aux_e5_cwinv_sqrt_xlate", range(3)),
            run_dirs("temporal", "_e10_cwinv_sqrt_xlate", range(3)), ["all", "non_derived"])
    compare(lines, df, "reference (all data, seeds 0–2): auxiliary 5 epochs − baseline 10 epochs", run_dirs("temporal", "_aux_e5_cwinv_sqrt", range(3)),
            run_dirs("temporal", "_e10_cwinv_sqrt", range(3)), ["all", "non_derived"])

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
