"""Summary of the CWE auxiliary-task control (CPU): is the gain of the v3.1 auxiliary task only due to the auxiliary model seeing about
60,000 more CVE descriptions and one more supervision signal? (Note S6)

Three groups of runs (scripts/run_cwe_control.sh; T2 temporal split; configuration selected in W4: 5 epochs, inv_sqrt class weighting,
λ = 0.5; seeds 0-2), all with the description only as input (--no_cwe_in_text; if the CWE identifier were in the input, predicting the
CWE class would amount to copying the input, and the control would be meaningless):
  none_desc   no auxiliary task;
  v31_desc    v3.1 auxiliary task (as in W4, only without the CWE identifier in the input);
  cwe_desc    CWE auxiliary task: the same auxiliary samples (same pool, same seed), supervised with their first CWE
              (top 50 + other, 51 classes).
References: the W4 baseline / v3.1 auxiliary model (input with the CWE identifier), seeds 0-2 paired with the above; the per-metric
section also lists seeds 0-4.
The output is descriptive and draws no conclusion (the reading rules were fixed before the results were seen):
  - mean ± standard deviation of each group (all test labels / without derived); best epoch of each run;
  - paired bootstrap (aggregate_seeds.paired_bootstrap, 1,000 resamples, averaged over seeds first, 95% percentile intervals);
  - per-metric macro-F1 differences, averaged separately over the 7 metrics with a v3.1 counterpart and the 4 without (AT, SC, SI, SA);
  - coverage of the CWE supervision (cwe_vocab.json of each CWE auxiliary run).
Usage: python src/cwe_control.py [--enc folder with the run directories] [--out output folder] [--boot 1000]
Output: results/cwe_control/summary.md
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import BOOT_KEYS, paired_bootstrap  # noqa: E402
from baselines_v0 import M40, evaluate, load, source_type_map  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
STEM = "T2_temporal_deberta-v3-base_none"
GROUPS = {"none_desc": "_desconly", "v31_desc": "_aux_desconly", "cwe_desc": "_auxcwe_desconly", "none_w4": "", "v31_w4": "_aux"}
LABELS = {"none_desc": "no auxiliary (description only)", "v31_desc": "v3.1 auxiliary (description only)", "cwe_desc": "CWE auxiliary (description only)",
          "none_w4": "no auxiliary (W4, description + CWE)", "v31_w4": "v3.1 auxiliary (W4, description + CWE)"}
SHORT = {"none_desc": "none", "v31_desc": "v31", "cwe_desc": "CWE", "none_w4": "none(W4)", "v31_w4": "v31(W4)"}
SEEDS = [0, 1, 2]
CONTRASTS = [("v31_desc", "none_desc"), ("cwe_desc", "none_desc"), ("v31_desc", "cwe_desc"), ("v31_w4", "none_w4")]
NEW4 = ["AT", "SC", "SI", "SA"]  # v4.0 新增或重构、没有直接 v3.1 对应项的指标（第 7.3 节）
SHARED = [k for k in M40 if k not in NEW4]
V4S = ["AT", "UI", "SC", "SI", "SA"]  # v4-specific F1 的口径（第 5 节）
KEYS = [("mean_macro_f1", "macro-F1"), ("v4_specific_f1", "v4-F1"), ("exact_match", "exact"), ("score_mae", "MAE"),
        ("band_acc", "band"), ("under_rate", "under"), ("hc_recall", "H+C rec.")]
SCOPES = [("all", "all test labels"), ("non_derived", "without derived")]


def run_dirs(enc, group, seeds=SEEDS):
    """Returns {seed: run directory} (only runs with a prediction file)."""
    out = {}
    for s in seeds:
        d = enc / f"{STEM}{GROUPS[group]}_e5_cwinv_sqrt_s{s}"
        if (d / "pred_latent.parquet").exists():
            out[s] = d
    return out


def scores(df, d):
    """Metrics of one run on both scopes, and the macro-F1 of each of the 11 metrics (keys f1_AV etc.)."""
    p = pd.read_parquet(d / "pred_latent.parquet")
    t = df.set_index("cve_id").loc[p["cve_id"]].reset_index()
    out = {}
    for scope, m in [("all", np.ones(len(t), bool)), ("non_derived", (t["label_type"] != "derived").to_numpy())]:
        r = evaluate(t[m].reset_index(drop=True), p[m].reset_index(drop=True))
        pm = {k: r["per_metric"][k]["macro_f1"] for k in M40}
        out[scope] = {k: r[k] for k, _ in KEYS if k in r} | {"v4_specific_f1": float(np.mean([pm[k] for k in V4S]))} \
            | {"f1_" + k: v for k, v in pm.items()}
    return out


def per_metric_delta(ra, rb, scope):
    """Per-metric macro-F1 differences (A − B, each averaged over seeds first)."""
    avg = lambda rs, k: np.mean([r[scope]["f1_" + k] for r in rs.values()])  # noqa: E731
    return {k: avg(ra, k) - avg(rb, k) for k in M40}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--enc", default=str(ROOT / "results" / "encoder"), help="folder with the run directories")
    ap.add_argument("--out", default=str(ROOT / "results" / "cwe_control"), help="output folder")
    ap.add_argument("--boot", type=int, default=1000, help="number of resamples of the paired bootstrap (0 = none)")
    args = ap.parse_args()
    enc, out = Path(args.enc), Path(args.out)
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")

    dirs = {g: run_dirs(enc, g) for g in GROUPS}
    dirs5 = {g: run_dirs(enc, g, range(5)) for g in ["none_w4", "v31_w4"]}
    res = {g: {s: scores(df, d) for s, d in ds.items()} for g, ds in dirs.items()}
    res5 = {g: {s: res[g][s] if s in res[g] else scores(df, d) for s, d in ds.items()} for g, ds in dirs5.items()}
    missing = [f"{g} seed {s}" for g in GROUPS for s in SEEDS if s not in dirs[g]]

    lines = ["# CWE auxiliary-task control (T2 temporal split, generated automatically)\n",
             "The first three groups use only the description as input (no CWE identifier); the two W4 groups (description + CWE identifier) are references. Configuration: 5 epochs, inv_sqrt class weighting, λ = 0.5; seeds 0–2.\n"]
    if missing:
        lines.append(f"**Missing runs**: {', '.join(missing)}\n")

    # 1. 各组均值 ± 标准差
    for scope, name in SCOPES:
        lines += [f"\n## Mean ± standard deviation of each group ({name})\n",
                  "| Group | Seeds | " + " | ".join(c for _, c in KEYS) + " |", "|---|---|" + "---|" * len(KEYS)]
        for g, rs in res.items():
            if rs:
                vals = [[r[scope][k] for r in rs.values()] for k, _ in KEYS]
                lines.append(f"| {LABELS[g]} | {len(rs)} | " + " | ".join(
                    f"{np.mean(v):.3f} ± {np.std(v, ddof=1) if len(v) > 1 else 0:.3f}" for v in vals) + " |")

    # 2. 配对 bootstrap（paired_bootstrap 计算"第三个参数 − 第二个参数"）
    lines += [f"\n## Paired bootstrap (A − B; averaged over seeds first; {args.boot:,} resamples; 95% percentile intervals)\n",
              "| A − B | Scope | n | Seeds (A/B) | Mean macro-F1 difference | Band accuracy difference | Underestimation difference | Score MAE difference |", "|---|---|---|---|---|---|---|---|"]
    for a, b in CONTRASTS:
        if dirs[a] and dirs[b] and args.boot > 0:
            for scope, x in paired_bootstrap(df, dirs[b], dirs[a], B=args.boot).items():
                cells = " | ".join(f"{x[k][0]:+.3f} [{x[k][1]:+.3f}, {x[k][2]:+.3f}]" for k in BOOT_KEYS)
                lines.append(f"| {SHORT[a]} − {SHORT[b]} | {dict(SCOPES)[scope]} | {x['n']:,} | {len(dirs[a])}/{len(dirs[b])} | {cells} |")
    lines.append("\nGroup names: none = no auxiliary task, v31 = v3.1 auxiliary task, CWE = CWE auxiliary task (all with the description only); (W4) = input with the CWE identifier. "
                 "Lower underestimation rate and MAE are better, so a negative difference in these two columns is an improvement.")

    # 3. 逐指标宏 F1 的差值
    cols = [(f"{SHORT[a]} − {SHORT[b]}", res[a], res[b]) for a, b in CONTRASTS if res[a] and res[b]]
    if res5["v31_w4"] and res5["none_w4"]:
        cols.append((f"v31(W4) − none(W4), seeds 0–{max(res5['v31_w4'])}", res5["v31_w4"], res5["none_w4"]))
    for scope, name in SCOPES:
        if not cols:
            break
        deltas = [per_metric_delta(ra, rb, scope) for _, ra, rb in cols]
        lines += [f"\n## Per-metric macro-F1 differences ({name}; each group averaged over seeds first)\n",
                  "| Metric | " + " | ".join(c for c, _, _ in cols) + " |", "|---|" + "---|" * len(cols)]
        lines += [f"| {k} | " + " | ".join(f"{d[k]:+.3f}" for d in deltas) + " |" for k in M40]
        for label, ks in [(f"mean of the {len(SHARED)} metrics with a v3.1 counterpart", SHARED), (f"mean of {'/'.join(NEW4)}", NEW4), ("mean of the 11 metrics", M40)]:
            lines.append(f"| **{label}** | " + " | ".join(f"{np.mean([d[k] for k in ks]):+.3f}" for d in deltas) + " |")

    # 4. 各运行的最佳轮次（判断是否欠训练）与 CWE 监督的覆盖率
    lines += ["\n## Best epoch of each run (selected by mean validation macro-F1; epochs counted from 0, 5 epochs)\n", "| Group | Seed | Best epoch | Mean validation macro-F1 |", "|---|---|---|---|"]
    for g in GROUPS:
        for s, d in dirs[g].items():
            r = json.loads((d / "results.json").read_text(encoding="utf-8"))
            lines.append(f"| {LABELS[g]} | {s} | {r['best_epoch']} | {r['val_best_mean_f1']:.3f} |")
    infos = {s: json.loads((d / "cwe_vocab.json").read_text(encoding="utf-8")) for s, d in dirs["cwe_desc"].items() if (d / "cwe_vocab.json").exists()}
    if infos:
        lines += ["\n## Coverage of the CWE supervision (CWE auxiliary runs; class table built on the training part only)\n",
                  "| Seed | v4 training samples | Auxiliary samples | v4 samples with a CWE | Auxiliary samples with a CWE | Share of 'other' among samples with a CWE | Top 5 CWEs |", "|---|---|---|---|---|---|---|"]
        for s, i in infos.items():
            lines.append(f"| {s} | {i['n_v4_rows']:,} | {i['n_aux_rows']:,} | {i['cwe_coverage_v4']:.1%} | {i['cwe_coverage_aux']:.1%} | "
                         f"{i['share_other']:.1%} | {', '.join(i['vocab'][:5])} |")

    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
