"""W5 label-efficiency curves (CPU): the baseline and the v3.1 auxiliary model with only 5% / 10% / 25% / 50% of the v4 training labels.

- The 100% point is the configuration selected in W4 on the temporal split (seeds 0-4; the curve uses only seeds 0-2, matching the
  number of seeds of the other fractions; the table also lists the 5-seed mean);
- metrics are recomputed from pred_latent.parquet with evaluate(), on all test labels and without derived labels;
- for each fraction, the same paired bootstrap as within the splits (aux − none, averaged over seeds first, 1,000 resamples, 95% interval).
Output: results/label_efficiency/summary.md, data.csv; Figure S1: paper/figures/fig3_label_efficiency.{pdf,png}
"""

import shutil
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import paired_bootstrap  # noqa: E402
from baselines_v0 import evaluate, load, source_type_map  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
OUT = ROOT / "results" / "label_efficiency"
FIG = ROOT / "paper" / "figures"
FRACS = [0.05, 0.1, 0.25, 0.5, 1.0]
N_TRAIN = 14488  # 时间划分的 v4 训练集（不含验证集）
KEYS = ["mean_macro_f1", "band_acc", "under_rate", "score_mae", "exact_match"]


def run_dirs(frac, ver):
    """Returns {seed: run directory}."""
    stem = "T2_temporal_deberta-v3-base_none" + ("_aux_e5" if ver == "aux" else "_e*") + "_cwinv_sqrt"
    pat = stem + (f"_frac{frac:g}_s[0-9]" if frac < 1 else "_s[0-9]")
    out = {}
    for d in ENC.glob(pat):
        if not (d / "pred_latent.parquet").exists():
            continue
        if frac == 1.0 and ("frac" in d.name or (ver == "none" and "_e5_" not in d.name)):
            continue
        out[int(d.name.rsplit("_s", 1)[1])] = d
    return dict(sorted(out.items()))


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    rows = []
    for frac in FRACS:
        for ver in ["none", "aux"]:
            for seed, d in run_dirs(frac, ver).items():
                p = pd.read_parquet(d / "pred_latent.parquet")
                t = df.set_index("cve_id").loc[p["cve_id"]].reset_index()
                for scope, m in [("all", np.ones(len(t), bool)), ("non_derived", (t["label_type"] != "derived").to_numpy())]:
                    r = evaluate(t[m].reset_index(drop=True), p[m].reset_index(drop=True))
                    rows.append({"frac": frac, "n_labels": round(N_TRAIN * frac), "version": ver, "seed": seed, "scope": scope,
                                 **{k: r[k] for k in KEYS}})
    data = pd.DataFrame(rows)
    OUT.mkdir(parents=True, exist_ok=True)
    data.to_csv(OUT / "data.csv", index=False)

    lines = ["# Label-efficiency curves (T2 temporal split, generated automatically)\n",
             "- 5%–50%: 3 seeds (0–2) per fraction; the training labels are sampled at random per seed; validation set, test set and auxiliary samples unchanged; ",
             "- 100%: configuration selected in W4; in the table, \"100% (seeds 0–2)\" matches the curve and \"100% (seeds 0–4)\" is the 5-seed mean of the W4 main runs; ",
             "- the number of training epochs of the baseline is scaled with the fraction (5% and 10%: 50 epochs; 25%: 20 epochs; 50%: 10 epochs; 100%: 5 epochs); the auxiliary variant always uses 5 epochs.\n"]
    for scope, title in [("all", "all test labels (21,900)"), ("non_derived", "without derived labels (16,749)")]:
        lines += [f"\n## {title}: mean ± standard deviation\n", "| v4 training labels | Variant | Seeds | " + " | ".join(KEYS) + " |", "|---|---|---|" + "---|" * len(KEYS)]
        for frac in FRACS:
            for ver in ["none", "aux"]:
                sets = [("", data[(data.frac == frac) & (data.version == ver) & (data.scope == scope) & (data.seed <= 2)])]
                if frac == 1.0:
                    sets.append((" (seeds 0–4)", data[(data.frac == frac) & (data.version == ver) & (data.scope == scope)]))
                for tag, g in sets:
                    if g.empty:
                        continue
                    lab = f"{frac:.0%} ({round(N_TRAIN * frac):,}){tag}"
                    lines.append(f"| {lab} | {'auxiliary' if ver == 'aux' else 'baseline'} | {len(g)} | "
                                 + " | ".join(f"{g[k].mean():.3f} ± {g[k].std(ddof=1):.3f}" for k in KEYS) + " |")

    if "--plot_only" in sys.argv:  # 只重画图 S1，不重算汇总表
        plot(df, data)
        return
    lines += ["\n## Paired bootstrap for each fraction (auxiliary − baseline; seeds 0–2 averaged first; 1,000 resamples; 95% interval)\n",
              "| v4 training labels | Scope | Mean macro-F1 difference | Band accuracy difference | Underestimation difference | Score MAE difference |", "|---|---|---|---|---|---|"]
    for frac in FRACS:
        none = {s: d for s, d in run_dirs(frac, "none").items() if s <= 2}
        aux = {s: d for s, d in run_dirs(frac, "aux").items() if s <= 2}
        if not none or not aux:
            continue
        res = paired_bootstrap(df, none, aux, B=1000)
        for scope, r in res.items():
            cells = " | ".join(f"{r[k][0]:+.3f} [{r[k][1]:+.3f}, {r[k][2]:+.3f}]" for k in ["mean_macro_f1", "band_acc", "under_rate", "score_mae"])
            lines.append(f"| {frac:.0%} | {'all' if scope == 'all' else 'without derived'} | {cells} |")
    (OUT / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    plot(df, data)


def plot(df, data):
    """Figure S1: two panels (mean macro-F1, underestimation rate), all test labels, mean ± standard deviation over seeds 0-2.
    Drawn at text width 1:1; y-axis label Underestimation; the baseline selected for Table 2 (25 epochs, all labels, seeds 0-2) is added
    as a reference; the figure is copied to paper/latex/figures/ (the copy used by the LaTeX build)."""
    ref = []
    for s in range(3):
        d = ENC / f"T2_temporal_deberta-v3-base_none_e25_cwinv_sqrt_s{s}"
        pr = pd.read_parquet(d / "pred_latent.parquet")
        tr = df.set_index("cve_id").loc[pr["cve_id"]].reset_index()
        ref.append(evaluate(tr, pr))
    plt.rcParams.update({"font.family": "Arial", "font.size": 8, "axes.linewidth": 0.6})
    fig, axes = plt.subplots(1, 2, figsize=(5.4, 2.5))
    style = {"none": dict(color="#6E6E6E", ls="--", marker="s", label="without auxiliary task"),
             "aux": dict(color="#0072B2", ls="-", marker="o", label="with v3.1 auxiliary task")}
    for ax, key, ylab in [(axes[0], "mean_macro_f1", "Mean macro-F1"), (axes[1], "under_rate", "Underestimation rate")]:
        for ver in ["none", "aux"]:
            g = data[(data.version == ver) & (data.scope == "all") & (data.seed <= 2)].groupby("n_labels")[key]
            m, s = g.mean(), g.std(ddof=1)
            ax.errorbar(m.index, m.values, yerr=s.values, capsize=2.5, lw=1.2, ms=4, **style[ver])
        rv = [r[key] for r in ref]
        ax.errorbar([N_TRAIN], [np.mean(rv)], yerr=[np.std(rv, ddof=1)], capsize=2.5, lw=1.0, ms=5, marker="D", mfc="white",
                    color="#6E6E6E", ls="none", label="without auxiliary task, 25 epochs")
        ax.set_xscale("log")
        ticks = [round(N_TRAIN * f) for f in FRACS]
        ax.set_xticks(ticks)
        ax.set_xticklabels([f"{t:,}\n({f:.0%})" for t, f in zip(ticks, FRACS)], fontsize=7)
        ax.minorticks_off()
        ax.set_xlabel("v4.0 training labels")
        ax.set_ylabel(ylab)
        ax.grid(axis="y", lw=0.4, alpha=0.5)
        ax.spines[["top", "right"]].set_visible(False)
    h, lab = axes[0].get_legend_handles_labels()
    fig.legend(h, lab, frameon=False, fontsize=7, loc="lower center", ncol=3, columnspacing=1.2, handletextpad=0.4)
    axes[0].set_title("(a)", fontsize=8, loc="left")
    axes[1].set_title("(b)", fontsize=8, loc="left")
    fig.tight_layout(rect=[0, 0.07, 1, 1])
    FIG.mkdir(parents=True, exist_ok=True)
    for ext in ("pdf", "png"):
        fig.savefig(FIG / f"fig3_label_efficiency.{ext}", dpi=300)
    latex_fig = FIG.parent / "latex" / "figures"
    latex_fig.mkdir(parents=True, exist_ok=True)
    shutil.copy2(FIG / "fig3_label_efficiency.pdf", latex_fig / "fig3_label_efficiency.pdf")


if __name__ == "__main__":
    main()
