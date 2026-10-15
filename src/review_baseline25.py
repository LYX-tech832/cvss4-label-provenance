"""Tables recomputed with the selected 25-epoch baseline (CPU, about 15 minutes). The baseline without the auxiliary task in Table 2
is the 25-epoch model selected on the validation set; this script recomputes, with the same definitions, the following tables with it:

1. DeBERTa rows of Table 4 (LLM sample); the row of the auxiliary model is recomputed as a check.
2. DeBERTa column of Table S5 (per-metric macro-F1, all / non-derived) and the mean gain on the shared and the new metrics.
3. Two additional rows of Table S11 (baseline 25 epochs, shuffled v3.1 labels; seeds 0-2).
4. DeBERTa rows of Table S15 (label-substitution control).
5. DeBERTa column of Table S18 (per source).
6. Rows aux − DeBERTa of Table S21 (vendor clusters).
7. Macro-F1 averaged only over the values present, in the note of Table S22.
Output: results/review_checks/summary9.md
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded, fast_scores  # noqa: E402
from baselines_v0 import CUTOFF, M31, M40, evaluate, load, source_type_map  # noqa: E402
from review_checks6 import cluster_boot, present_f1, vendors  # noqa: E402
from rq1_stats import rule_convert  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
PRED = ROOT / "results" / "baselines_v0" / "predictions"
OUT = ROOT / "results" / "review_checks" / "summary9.md"
STEM = "T2_temporal_deberta-v3-base_none"
SHARED, NEW = ["AV", "AC", "PR", "UI", "VC", "VI", "VA"], ["AT", "SC", "SI", "SA"]
rng = np.random.default_rng(0)


def frames(tag, seeds, ids):
    return [pd.read_parquet(ENC / f"{STEM}{tag}_s{s}" / "pred_latent.parquet").set_index("cve_id").loc[ids].reset_index() for s in seeds]


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    ids = test["cve_id"]
    t = Encoded(test, "y_")
    fr = {"none25": frames("_e25_cwinv_sqrt", range(5), ids), "aux": frames("_aux_e5_cwinv_sqrt", range(5), ids),
          "none5": frames("_e5_cwinv_sqrt", range(5), ids)}
    enc = {k: [Encoded(p) for p in v] for k, v in fr.items()}
    enc["tfidf"] = [Encoded(pd.read_parquet(PRED / "T2_temporal_tfidf_lr.parquet").set_index("cve_id").loc[ids].reset_index())]
    nd = (test["label_type"] != "derived").to_numpy()
    lines = ["# Tables recomputed with the selected 25-epoch baseline (generated automatically)\n"]

    # 1 表 9
    llm_ids = pd.read_parquet(ROOT / "results" / "autocvss_baseline" / "deepseek-v4-pro_DTD_s0" / "predictions.parquet")["cve_id"]
    s = df.set_index("cve_id").loc[llm_ids].reset_index()
    ts = Encoded(s, "y_")
    lt = s["label_type"].to_numpy()
    scopes = [np.arange(len(s)), np.flatnonzero(lt != "derived")] + [np.flatnonzero(lt == ty) for ty in ["derived", "independent", "v4_only", "other"]]
    lines += ["## 1. Table 4 (LLM sample, 2,000 CVEs): mean macro-F1 / band accuracy\n", "| Model | Whole sample | Non-derived | derived | undetected | v4-only | other |", "|---|---|---|---|---|---|---|"]
    for name, tag in [("DeBERTa (25 epochs, 5 seeds)", "_e25_cwinv_sqrt"), ("DeBERTa (5 epochs, 5 seeds)", "_e5_cwinv_sqrt"), ("DeBERTa + auxiliary (5 seeds)", "_aux_e5_cwinv_sqrt")]:
        es = [Encoded(p) for p in frames(tag, range(5), llm_ids)]
        cells = []
        for ix in scopes:
            rs = [fast_scores(ts, e, ix) for e in es]
            cells.append(f"{np.mean([r['mean_macro_f1'] for r in rs]):.3f} / {np.mean([r['band_acc'] for r in rs]):.3f}")
        lines.append(f"| {name} | " + " | ".join(cells) + " |")

    # 2 表 S5
    lines += ["\n## 2. Table S5: per-metric macro-F1 (all / non-derived), mean over 5 seeds\n", "| Metric | DeBERTa 25 epochs | DeBERTa + auxiliary | Gain (all) |", "|---|---|---|---|"]
    pm = {}
    for key in ["none25", "aux"]:
        for scope, m in [("all", np.ones(len(test), bool)), ("nd", nd)]:
            rs = [evaluate(test[m].reset_index(drop=True), p[m].reset_index(drop=True))["per_metric"] for p in fr[key]]
            pm[(key, scope)] = {k: np.mean([r[k]["macro_f1"] for r in rs]) for k in M40}
    for k in M40:
        lines.append(f"| {k} | {pm[('none25', 'all')][k]:.3f} / {pm[('none25', 'nd')][k]:.3f} | {pm[('aux', 'all')][k]:.3f} / {pm[('aux', 'nd')][k]:.3f} | {pm[('aux', 'all')][k] - pm[('none25', 'all')][k]:+.3f} |")
    g = {k: pm[("aux", "all")][k] - pm[("none25", "all")][k] for k in M40}
    lines.append(f"\nMean gain on the 7 shared metrics ({', '.join(SHARED)}) {np.mean([g[k] for k in SHARED]):+.3f}; on the 4 new metrics ({', '.join(NEW)}) {np.mean([g[k] for k in NEW]):+.3f}; "
                 f"largest two gains: " + ", ".join(f"{k} {v:+.3f}" for k, v in sorted(g.items(), key=lambda x: -x[1])[:2]) + ".")

    # 3 表 S11
    lines += ["\n## 3. Additional rows of Table S11 (all labels, seeds 0–2)\n", "| Model | " + " | ".join(M40) + " |", "|---|" + "---|" * len(M40)]
    for name, tag in [("baseline 25 epochs", "_e25_cwinv_sqrt"), ("shuffled v3.1 labels 5 epochs", "_auxshuf_e5_cwinv_sqrt")]:
        rs = [evaluate(test, p)["per_metric"] for p in frames(tag, range(3), ids)]
        lines.append(f"| {name} | " + " | ".join(f"{np.mean([r[k]['macro_f1'] for r in rs]):.3f}" for k in M40) + " |")

    # 4 表 S15
    sub = test[test["has_v31"] & nd].reset_index(drop=True)
    conv = [rule_convert({k: r["x31_" + k] for k in M31}) for _, r in sub.iterrows()]
    sub_r = sub.copy()
    for k in M40:
        sub_r["y_" + k] = [c[k] for c in conv]
    to, tc = Encoded(sub, "y_"), Encoded(sub_r, "y_")
    es = [Encoded(p) for p in frames("_e25_cwinv_sqrt", range(5), sub["cve_id"])]
    vc = (sub["source"] == "VulnCheck").to_numpy()
    lines += ["\n## 4. DeBERTa (25 epochs) rows of Table S15: label-substitution control\n", "| Scope | Band accuracy original → rule R | Difference [95%] | Underestimation original → rule R | Difference [95%] |", "|---|---|---|---|---|"]
    for scope, m in [(f"all ({len(sub):,})", np.ones(len(sub), bool)), (f"VulnCheck ({int(vc.sum()):,})", vc), (f"without VulnCheck ({int((~vc).sum()):,})", ~vc)]:
        idx = np.flatnonzero(m)

        def sc(tt, ix):
            rs = [fast_scores(tt, e, ix) for e in es]
            return np.array([np.mean([r[k] for r in rs]) for k in ("band_acc", "under_rate")])
        a, b = sc(to, idx), sc(tc, idx)
        bs = np.array([sc(tc, ix) - sc(to, ix) for ix in (rng.choice(idx, size=len(idx), replace=True) for _ in range(1000))])
        ci = lambda j: f"{b[j] - a[j]:+.3f} [{np.percentile(bs[:, j], 2.5):+.3f}, {np.percentile(bs[:, j], 97.5):+.3f}]"  # noqa: E731
        lines.append(f"| {scope} | {a[0]:.3f} → {b[0]:.3f} | {ci(0)} | {a[1]:.3f} → {b[1]:.3f} | {ci(1)} |")

    # 5 表 S18
    lines += ["\n## 5. DeBERTa (25 epochs) column of Table S18: each source (at least 200 CVEs), mean macro-F1 / band accuracy\n", "| Source | n | DeBERTa 25 epochs | DeBERTa + auxiliary | Auxiliary better (macro-F1) |", "|---|---|---|---|---|"]
    n_better = 0
    for src, n in test["source"].value_counts().items():
        if n < 200:
            continue
        idx = np.flatnonzero(test["source"].to_numpy() == src)
        c = {}
        for key in ["none25", "aux"]:
            rs = [fast_scores(t, e, idx) for e in enc[key]]
            c[key] = (np.mean([r["mean_macro_f1"] for r in rs]), np.mean([r["band_acc"] for r in rs]))
        n_better += c["aux"][0] > c["none25"][0]
        lines.append(f"| {src} | {n:,} | {c['none25'][0]:.3f} / {c['none25'][1]:.3f} | {c['aux'][0]:.3f} / {c['aux'][1]:.3f} | {'yes' if c['aux'][0] > c['none25'][0] else 'no'} |")
    lines.append(f"\nSources where the auxiliary model has the higher mean macro-F1: {n_better}.")

    # 6 表 S21
    v = vendors(ids)
    cl = np.array([v.get(c) or c for c in ids])
    lines += ["\n## 6. Table S21: vendor clusters (baseline = 25 epochs without the auxiliary task)\n", "| Comparison | Scope | Difference | Resampling CVEs | Resampling vendor clusters |", "|---|---|---|---|---|"]
    for name, idx in [("all", np.arange(len(test))), ("non-derived", np.flatnonzero(nd))]:
        for a, b, key in [("aux", "none25", "mean_macro_f1"), ("aux", "none25", "band_acc"), ("aux", "tfidf", "mean_macro_f1")]:
            def f(ix, a=a, b=b, key=key):
                return np.mean([fast_scores(t, e, ix)[key] for e in enc[a]]) - np.mean([fast_scores(t, e, ix)[key] for e in enc[b]])
            cve = np.percentile([f(rng.choice(idx, size=len(idx), replace=True)) for _ in range(1000)], [2.5, 97.5])
            clu = cluster_boot(cl, idx, f)
            lines.append(f"| {a} − {b} ({key}) | {name} | {f(idx):+.3f} | [{cve[0]:+.3f}, {cve[1]:+.3f}] | [{clu[0]:+.3f}, {clu[1]:+.3f}] |")

    # 7 表 S22 说明
    allx = np.arange(len(test))
    lines += ["\n## 7. Note of Table S22: macro-F1 averaged only over the values present (temporal split test set, all / non-derived)\n", "| Method | All | Non-derived |", "|---|---|---|"]
    for name, key in [("TF-IDF", "tfidf"), ("DeBERTa 25 epochs", "none25"), ("DeBERTa + auxiliary", "aux")]:
        lines.append(f"| {name} | {np.mean([present_f1(t, e, allx) for e in enc[key]]):.3f} | {np.mean([present_f1(t, e, np.flatnonzero(nd)) for e in enc[key]]):.3f} |")

    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
