"""Summary of the GPU runs for the shuffled-label control and the ten-epoch LOSO baselines (CPU, a few minutes):

1. Negative control with shuffled v3.1 labels (temporal split, --aux_shuffle, seeds 0-2): compared with the baseline (5 and 10 epochs),
   the normal v3.1 auxiliary task, the CWE auxiliary task and pseudo-labels, on all, non-derived, R-inconsistent (dual-scored and
   v4.0 ≠ rule R(same-source v3.1)) and no-same-source-v3.1 labels; also the share of AT:Present predicted as None.
2. The baseline trained for 10 epochs on the three LOSO splits (seeds 0-4, as many as are finished): compared with the baseline and the
   auxiliary model at 5 epochs.
Differences: paired bootstrap (test CVEs resampled 1,000 times, each variant averaged over its seeds; with different numbers of seeds,
only the common seeds are used).
Output: results/review_gpu/summary2.md
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded, fast_scores  # noqa: E402
from baselines_v0 import CUTOFF, evaluate, load, source_type_map  # noqa: E402
from review_checks import clean_mask  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
OUT = ROOT / "results" / "review_gpu" / "summary2.md"
SHARED = ["AV", "AC", "PR", "UI", "VC", "VI", "VA"]
NEW = ["AT", "SC", "SI", "SA"]


def runs(stem, tag, seeds):
    return [ENC / f"{stem}{tag}_s{s}" for s in seeds if (ENC / f"{stem}{tag}_s{s}" / "pred_latent.parquet").exists()]


def read(paths, ids):
    return [pd.read_parquet(p / "pred_latent.parquet").set_index("cve_id").loc[ids].reset_index() for p in paths]


def boot(t, enc, a, b, idx, rng, B=1000):
    k = min(len(enc[a]), len(enc[b]))

    def d(ix):
        fa = [fast_scores(t, e, ix) for e in enc[a][:k]]
        fb = [fast_scores(t, e, ix) for e in enc[b][:k]]
        return (np.mean([x["mean_macro_f1"] for x in fa]) - np.mean([x["mean_macro_f1"] for x in fb]),
                np.mean([x["band_acc"] for x in fa]) - np.mean([x["band_acc"] for x in fb]))
    pt = d(idx)
    bs = np.array([d(rng.choice(idx, size=len(idx), replace=True)) for _ in range(B)])
    ci = lambda j: f"{pt[j]:+.3f} [{np.percentile(bs[:, j], 2.5):+.3f}, {np.percentile(bs[:, j], 97.5):+.3f}]"  # noqa: E731
    return k, ci(0), ci(1)


def part1(df, lines):
    stem = "T2_temporal_deberta-v3-base_none"
    vers = {"baseline 5 epochs": ("_e5_cwinv_sqrt", range(5)), "baseline 10 epochs": ("_e10_cwinv_sqrt", range(3)),
            "shuffled v3.1 auxiliary 5 epochs": ("_auxshuf_e5_cwinv_sqrt", range(3)), "v3.1 auxiliary 5 epochs": ("_aux_e5_cwinv_sqrt", range(5)),
            "v3.1 auxiliary 10 epochs": ("_aux_e10_cwinv_sqrt", range(3)), "CWE auxiliary 5 epochs": ("_auxcwe_desconly_e5_cwinv_sqrt", range(3)),
            "pseudo-labels 5 epochs": ("_pseudo_e5_cwinv_sqrt", range(3))}
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    test["clean"] = clean_mask(test)
    ids = test["cve_id"]
    t = Encoded(test, "y_")
    preds = {v: read(runs(stem, tag, seeds), ids) for v, (tag, seeds) in vers.items()}
    enc = {v: [Encoded(p) for p in ps] for v, ps in preds.items()}
    subsets = {"all": np.ones(len(test), bool), "non-derived": (test["label_type"] != "derived").to_numpy(),
               "R-inconsistent": test["clean"].to_numpy(), "no same-source v3.1": (~test["has_v31"]).to_numpy()}
    lines.append("## 1. Negative control with shuffled v3.1 labels (temporal split)\n")
    for name, m in subsets.items():
        idx = np.flatnonzero(m)
        tt = test.iloc[idx].reset_index(drop=True)
        lines += [f"\n### {name}: n = {len(idx):,}\n", "| Variant | Seeds | Mean macro-F1 (mean ± sd) | Macro-F1 of the 7 shared metrics | Macro-F1 of AT/SC/SI/SA | Band accuracy |", "|---|---|---|---|---|---|"]
        for v, ps in preds.items():
            rs = [evaluate(tt, p.iloc[idx].reset_index(drop=True)) for p in ps]
            mf = [r["mean_macro_f1"] for r in rs]
            sh = np.mean([np.mean([r["per_metric"][k]["macro_f1"] for k in SHARED]) for r in rs])
            nw = np.mean([np.mean([r["per_metric"][k]["macro_f1"] for k in NEW]) for r in rs])
            lines.append(f"| {v} | {len(ps)} | {np.mean(mf):.3f} ± {np.std(mf, ddof=1):.3f} | {sh:.3f} | {nw:.3f} | {np.mean([r['band_acc'] for r in rs]):.3f} |")
        rng = np.random.default_rng(0)
        lines += ["\nPaired bootstrap (A − B; mean macro-F1 / band accuracy; 95% interval):\n", "| A − B | Common seeds | Mean macro-F1 difference | Band accuracy difference |", "|---|---|---|---|"]
        for a, b in [("v3.1 auxiliary 5 epochs", "shuffled v3.1 auxiliary 5 epochs"), ("shuffled v3.1 auxiliary 5 epochs", "baseline 5 epochs"), ("shuffled v3.1 auxiliary 5 epochs", "baseline 10 epochs"),
                     ("v3.1 auxiliary 5 epochs", "baseline 5 epochs"), ("shuffled v3.1 auxiliary 5 epochs", "CWE auxiliary 5 epochs"), ("v3.1 auxiliary 5 epochs", "CWE auxiliary 5 epochs")]:
            k, c0, c1 = boot(t, enc, a, b, idx, rng)
            lines.append(f"| {a} − {b} | {k} | {c0} | {c1} |")
    cm = test["clean"].to_numpy()
    atp = cm & (test["y_AT"] == "P").to_numpy()
    lines += [f"\n### AT: the {int(atp.sum()):,} labels of the R-inconsistent subset with AT:Present\n", "| Variant | Seeds | Share predicted as AT:None | Share predicted as AT:Present on the whole test set |", "|---|---|---|---|"]
    for v, ps in preds.items():
        share = np.mean([(p["AT"].to_numpy()[atp] == "N").mean() for p in ps])
        allp = np.mean([(p["AT"].to_numpy() == "P").mean() for p in ps])
        lines.append(f"| {v} | {len(ps)} | {share:.3f} | {allp:.3f} |")
    lines.append(f"\n(Share of AT:Present among the true labels of the whole test set: {(test['y_AT'] == 'P').mean():.3f})\n")


def part2(df, lines):
    lines.append("\n## 2. LOSO splits: baseline trained for 10 epochs\n")
    for split in ["VulnCheck", "GitHub_M", "VulDB"]:
        stem = f"T2_loso-{split}_deberta-v3-base_none"
        vers = {"baseline 5 epochs": runs(stem, "_e5_cwinv_sqrt", range(5)), "baseline 10 epochs": runs(stem, "_e10_cwinv_sqrt", range(5)),
                "v3.1 auxiliary 5 epochs": runs(stem, "_aux_e5_cwinv_sqrt", range(5))}
        if not vers["baseline 10 epochs"]:
            lines.append(f"\n### Held out {split}: no 10-epoch results yet\n")
            continue
        test = df[df["source"] == split].reset_index(drop=True)
        ids = test["cve_id"]
        t = Encoded(test, "y_")
        preds = {v: read(p, ids) for v, p in vers.items()}
        enc = {v: [Encoded(p) for p in ps] for v, ps in preds.items()}
        idx = np.arange(len(test))
        lines += [f"\n### Held out {split}: n = {len(test):,}\n", "| Variant | Seeds | Mean macro-F1 (mean ± sd) | Band accuracy | Underestimation |", "|---|---|---|---|---|"]
        for v, ps in preds.items():
            rs = [evaluate(test, p) for p in ps]
            mf = [r["mean_macro_f1"] for r in rs]
            sd = np.std(mf, ddof=1) if len(mf) > 1 else float("nan")
            lines.append(f"| {v} | {len(ps)} | {np.mean(mf):.3f} ± {sd:.3f} | {np.mean([r['band_acc'] for r in rs]):.3f} | "
                         f"{np.mean([r.get('under_rate', float('nan')) for r in rs]):.3f} |")
        rng = np.random.default_rng(0)
        lines += ["\n| A − B | Common seeds | Mean macro-F1 difference | Band accuracy difference |", "|---|---|---|---|"]
        for a, b in [("baseline 10 epochs", "baseline 5 epochs"), ("v3.1 auxiliary 5 epochs", "baseline 10 epochs"), ("v3.1 auxiliary 5 epochs", "baseline 5 epochs")]:
            k, c0, c1 = boot(t, enc, a, b, idx, rng)
            lines.append(f"| {a} − {b} | {k} | {c0} | {c1} |")


def part3(df, lines):
    """5% of the v4 training labels: normal vs shuffled v3.1 auxiliary task (run_review_gpu3.sh), with the baseline on all labels as reference."""
    stem = "T2_temporal_deberta-v3-base_none"
    vers = {"5% + v3.1 auxiliary": runs(stem, "_aux_e5_cwinv_sqrt_frac0.05", range(3)),
            "5% + shuffled v3.1 auxiliary": runs(stem, "_auxshuf_e5_cwinv_sqrt_frac0.05", range(3)),
            "all labels, baseline 5 epochs": runs(stem, "_e5_cwinv_sqrt", range(5)),
            "all labels, baseline 10 epochs": runs(stem, "_e10_cwinv_sqrt", range(3))}
    lines.append("\n## 3. Shuffled-label control with 5% of the v4 training labels (temporal split)\n")
    if not vers["5% + shuffled v3.1 auxiliary"]:
        lines.append("no results yet.\n")
        return
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    test["clean"] = clean_mask(test)
    ids = test["cve_id"]
    t = Encoded(test, "y_")
    preds = {v: read(p, ids) for v, p in vers.items()}
    enc = {v: [Encoded(p) for p in ps] for v, ps in preds.items()}
    cm = test["clean"].to_numpy()
    atp = cm & (test["y_AT"] == "P").to_numpy()
    for name, m in {"all": np.ones(len(test), bool), "non-derived": (test["label_type"] != "derived").to_numpy(), "R-inconsistent": cm}.items():
        idx = np.flatnonzero(m)
        tt = test.iloc[idx].reset_index(drop=True)
        lines += [f"\n### {name}: n = {len(idx):,}\n", "| Variant | Seeds | Mean macro-F1 (mean ± sd) | Band accuracy |", "|---|---|---|---|"]
        for v, ps in preds.items():
            rs = [evaluate(tt, p.iloc[idx].reset_index(drop=True)) for p in ps]
            mf = [r["mean_macro_f1"] for r in rs]
            sd = np.std(mf, ddof=1) if len(mf) > 1 else float("nan")
            lines.append(f"| {v} | {len(ps)} | {np.mean(mf):.3f} ± {sd:.3f} | {np.mean([r['band_acc'] for r in rs]):.3f} |")
        rng = np.random.default_rng(0)
        lines += ["\n| A − B | Common seeds | Mean macro-F1 difference | Band accuracy difference |", "|---|---|---|---|"]
        for a, b in [("5% + v3.1 auxiliary", "5% + shuffled v3.1 auxiliary"), ("5% + shuffled v3.1 auxiliary", "all labels, baseline 5 epochs"),
                     ("5% + shuffled v3.1 auxiliary", "all labels, baseline 10 epochs"), ("5% + v3.1 auxiliary", "all labels, baseline 10 epochs")]:
            k, c0, c1 = boot(t, enc, a, b, idx, rng)
            lines.append(f"| {a} − {b} | {k} | {c0} | {c1} |")
    lines += [f"\n### AT: share of the {int(atp.sum()):,} labels of the R-inconsistent subset with AT:Present that are predicted as None\n", "| Variant | Share |", "|---|---|"]
    for v, ps in preds.items():
        lines.append(f"| {v} | {np.mean([(p['AT'].to_numpy()[atp] == 'N').mean() for p in ps]):.3f} |")


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    lines = ["# Shuffled-label control and ten-epoch LOSO baselines (GPU runs; generated automatically)\n"]
    only = sys.argv[1:]  # 可只跑部分：python src/review_gpu2_summary.py 2 3
    if not only or "1" in only:
        part1(df, lines)
    if not only or "2" in only:
        part2(df, lines)
    if not only or "3" in only:
        part3(df, lines)
    out = OUT if not only else OUT.with_name(f"summary2_part{''.join(sorted(only))}.md")  # 只跑部分时不覆盖完整汇总
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
