"""Base-rate correction, a training-side experiment and rolling time cut-offs (CPU, about 20-30 minutes, mostly TF-IDF refits):

A. Base-rate correction: on the temporal split test set, for each label type and the main sources, the share of the most frequent band
   (base rate), each method's band accuracy, their difference, and Cohen's κ of the severity bands. Shows that the high scores on
   VulDB come mostly from its high base rate.
B. Training-side experiment: change of the TF-IDF baseline on the non-derived test labels and on each source when VulDB's labels are
   removed from its training set (paired bootstrap).
C. Rolling time cut-offs: the TF-IDF baseline is trained once at each of 5 cut-off dates and tested on the following quarter, comparing
   all labels with the labels without VulDB (the source typing uses only data before 2026, so "VulDB or not" is used instead).
Output: results/review_checks/summary8.md
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import cohen_kappa_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded, fast_scores  # noqa: E402
from baselines_v0 import CUTOFF, evaluate, load, pred_tfidf_lr, source_type_map  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
OUT = ROOT / "results" / "review_checks" / "summary8.md"
rng = np.random.default_rng(0)


def read(path, ids):
    return pd.read_parquet(path).set_index("cve_id").loc[ids].reset_index()


def part_a(df, test, lines):
    ids = test["cve_id"]
    t = Encoded(test, "y_")
    methods = {"TF-IDF + LR": [read(ROOT / "results" / "baselines_v0" / "predictions" / "T2_temporal_tfidf_lr.parquet", ids)],
               "DeBERTa (25 epochs, 5 seeds)": [read(ENC / f"T2_temporal_deberta-v3-base_none_e25_cwinv_sqrt_s{s}" / "pred_latent.parquet", ids) for s in range(5)],
               "DeBERTa + auxiliary (5 seeds)": [read(ENC / f"T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s{s}" / "pred_latent.parquet", ids) for s in range(5)]}
    enc = {m: [Encoded(p) for p in ps] for m, ps in methods.items()}
    groups = [("all", np.ones(len(test), bool)), ("non-derived", (test["label_type"] != "derived").to_numpy())]
    groups += [(f"type {k}", (test["label_type"] == k).to_numpy()) for k in ["derived", "independent", "v4_only", "other"]]
    groups += [(f"source {s}", (test["source"] == s).to_numpy()) for s in ["VulDB", "VulnCheck", "GitHub_M"]]
    lines += ["## A. Base-rate correction: severity bands (temporal split test set)\n",
              "Base rate = share of the most frequent band among the group's true bands (the band accuracy of always guessing that band). κ = unweighted Cohen's κ of the bands. DeBERTa averaged over 5 seeds.\n",
              "| Group | n | Base rate | " + " | ".join(f"{m}: accuracy / above base rate / κ" for m in methods) + " |", "|---|---|---|" + "---|" * len(methods)]
    for name, m in groups:
        idx = np.flatnonzero(m)
        tb = t.band[idx]
        base = np.bincount(tb[tb >= 0]).max() / len(tb)
        cells = []
        for mth in methods:
            acc = np.mean([(e.band[idx] == tb).mean() for e in enc[mth]])
            kap = np.mean([cohen_kappa_score(tb, e.band[idx]) for e in enc[mth]])
            cells.append(f"{acc:.3f} / {acc - base:+.3f} / {kap:.3f}")
        lines.append(f"| {name} | {len(idx):,} | {base:.3f} | " + " | ".join(cells) + " |")


def boot_diff(t, ea, eb, idx, B=1000):
    def d(ix):
        a, b = fast_scores(t, ea, ix), fast_scores(t, eb, ix)
        return a["mean_macro_f1"] - b["mean_macro_f1"], a["band_acc"] - b["band_acc"]
    pt = d(idx)
    bs = np.array([d(rng.choice(idx, size=len(idx), replace=True)) for _ in range(B)])
    return [f"{pt[j]:+.3f} [{np.percentile(bs[:, j], 2.5):+.3f}, {np.percentile(bs[:, j], 97.5):+.3f}]" for j in range(2)]


def part_b(df, test, lines):
    train = df[df["pub"] < CUTOFF]
    ids = test["cve_id"]
    full = read(ROOT / "results" / "baselines_v0" / "predictions" / "T2_temporal_tfidf_lr.parquet", ids)
    sub = train[train["source"] != "VulDB"]
    nov = pred_tfidf_lr(sub, test, with_v31=False).reset_index(drop=True)
    nov.insert(0, "cve_id", ids.values)
    nov.to_parquet(ROOT / "results" / "review_checks" / "T2_temporal_tfidf_lr_noVulDBtrain.parquet")
    t, ef, en = Encoded(test, "y_"), Encoded(full), Encoded(nov)
    lines += ["\n## B. VulDB's labels removed from the training set (TF-IDF + LR; same test set)\n",
              f"Training labels: all {len(train):,}; without VulDB {len(sub):,} (VulDB {len(train) - len(sub):,}, {(len(train) - len(sub)) / len(train):.1%}).\n",
              "| Test scope | n | Trained on all: mean macro-F1 / band accuracy | Trained without VulDB | Difference (without − all): mean macro-F1 | Band accuracy |", "|---|---|---|---|---|---|"]
    groups = [("non-derived", (test["label_type"] != "derived").to_numpy()), ("derived (VulDB)", (test["label_type"] == "derived").to_numpy()),
              ("type independent", (test["label_type"] == "independent").to_numpy()), ("type v4_only", (test["label_type"] == "v4_only").to_numpy()),
              ("type other", (test["label_type"] == "other").to_numpy()), ("source VulnCheck", (test["source"] == "VulnCheck").to_numpy()),
              ("source GitHub_M", (test["source"] == "GitHub_M").to_numpy())]
    for name, m in groups:
        idx = np.flatnonzero(m)
        a, b = fast_scores(t, ef, idx), fast_scores(t, en, idx)
        d = boot_diff(t, en, ef, idx)
        lines.append(f"| {name} | {len(idx):,} | {a['mean_macro_f1']:.3f} / {a['band_acc']:.3f} | {b['mean_macro_f1']:.3f} / {b['band_acc']:.3f} | {d[0]} | {d[1]} |")


def part_c(df, lines):
    lines += ["\n## C. Rolling time cut-offs (TF-IDF + LR; trained on the labels before the cut-off date, tested on the following quarter)\n",
              "| Cut-off date | Training | Test | Share of VulDB in the test set | All: mean macro-F1 / band accuracy | Without VulDB | Difference in band accuracy |", "|---|---|---|---|---|---|---|"]
    cuts = ["2025-07-01", "2025-10-01", "2026-01-01", "2026-04-01", "2026-07-01"]
    for c in cuts:
        c0 = pd.Timestamp(c, tz="UTC")
        c1 = c0 + pd.DateOffset(months=3)
        tr, te = df[df["pub"] < c0], df[(df["pub"] >= c0) & (df["pub"] < c1)].reset_index(drop=True)
        pred = pred_tfidf_lr(tr, te, with_v31=False).reset_index(drop=True)
        nv = (te["source"] != "VulDB").to_numpy()
        ra = evaluate(te, pred)
        rb = evaluate(te[nv].reset_index(drop=True), pred[nv].reset_index(drop=True))
        lines.append(f"| {c} | {len(tr):,} | {len(te):,} | {1 - nv.mean():.1%} | {ra['mean_macro_f1']:.3f} / {ra['band_acc']:.3f} | "
                     f"{rb['mean_macro_f1']:.3f} / {rb['band_acc']:.3f} | {ra['band_acc'] - rb['band_acc']:+.3f} |")
        print("done", c, flush=True)


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    lines = ["# Base-rate correction, training-side experiment and rolling time cut-offs (generated automatically)\n"]
    part_a(df, test, lines)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    part_b(df, test, lines)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    part_c(df, lines)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
