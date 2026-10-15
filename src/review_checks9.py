"""Predictability by source, back-filling and source-macro averages (CPU, about 10 minutes):

A. Decisive control: are VulDB's v3.1 labels also easier to predict than those of other sources?
   The same CVEs, the same model (TF-IDF + LR) and the same training/test split (the dual-scored CVEs of T1: training before 2026, test
   in 2026) predict the same CNA's v3.1 vector and its v4.0 vector; reported per source: base rate of the severity band, band accuracy,
   Cohen's κ and mean macro-F1. If VulDB's v3.1 labels are just as much easier to predict, the evaluation difference is a source effect
   and not caused by the derivation of the v4.0 labels.
B. Back-filling by VulnCheck: distribution of the CVE identifier years in the temporal split test set by source.
C. Source-macro averages: results on the temporal split test set with equal weight for each source (at least 30 test CVEs), and the
   gain of the auxiliary task.
D. Label types of the T1 test set.
E. Main results without the back-filled test CVEs (identifier year before 2025).
Output: results/review_checks/summary10.md
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd
from cvss import CVSS3
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import cohen_kappa_score, f1_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded, fast_scores  # noqa: E402
from baselines_v0 import CUTOFF, M31, M40, SEED, load, source_type_map  # noqa: E402
from cvss_utils import V31_METRICS, V40_METRICS  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
OUT = ROOT / "results" / "review_checks" / "summary10.md"
rng = np.random.default_rng(0)
BANDS = ["None", "Low", "Medium", "High", "Critical"]


def band31(frame, prefix):
    vec = "CVSS:3.1/" + frame[[prefix + k for k in M31]].apply(lambda r: "/".join(f"{k}:{v}" for k, v in zip(M31, r)), axis=1)
    cache = {}
    return np.array([cache.setdefault(v, BANDS.index(CVSS3(v).severities()[0])) for v in vec])


def fit_predict(train_text, test_text, ys):
    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=200_000, sublinear_tf=True)
    xtr, xte = vec.fit_transform(train_text), vec.transform(test_text)
    out = {}
    for k, y in ys.items():
        out[k] = [y[0]] * xte.shape[0] if len(set(y)) == 1 else LogisticRegression(C=4.0, max_iter=3000, random_state=SEED).fit(xtr, y).predict(xte)
    return pd.DataFrame(out)


def macro_f1(true, pred, values):
    return float(np.mean([f1_score(true[k], pred[k], labels=values[k], average="macro", zero_division=0) for k in pred.columns]))


def part_a(df, lines):
    d = df[df["has_v31"]]
    tr, te = d[d["pub"] < CUTOFF], d[d["pub"] >= CUTOFF].reset_index(drop=True)
    p31 = fit_predict(tr["text"], te["text"], {k: tr["x31_" + k].values for k in M31})
    p40 = fit_predict(tr["text"], te["text"], {k: tr["y_" + k].values for k in M40})
    t31 = te[["x31_" + k for k in M31]].set_axis(M31, axis=1)
    t40 = te[["y_" + k for k in M40]].set_axis(M40, axis=1)
    b31t, b31p = band31(te, "x31_"), band31(p31.add_prefix("p_"), "p_")
    e_t, e_p = Encoded(te, "y_"), Encoded(p40.assign(cve_id=te["cve_id"]))
    lines += ["## A. Predictability of the v3.1 and the v4.0 labels of the same CVEs (TF-IDF + LR; the dual-scored CVEs of T1)\n",
              f"Training: {len(tr):,} dual-scored CVEs before 2026; test: {len(te):,} in 2026. Input, training CVEs and test CVEs are identical for both models; only the version of the labels differs.\n",
              "| Source of the test labels | n | v3.1: base rate / band accuracy / κ / mean macro-F1 (8 metrics) | v4.0: base rate / band accuracy / κ / mean macro-F1 (11 metrics) |", "|---|---|---|---|"]
    groups = [("VulDB", (te["source"] == "VulDB").to_numpy()), ("all other sources", (te["source"] != "VulDB").to_numpy()),
              ("VulnCheck", (te["source"] == "VulnCheck").to_numpy()), ("other than VulDB and VulnCheck", (~te["source"].isin(["VulDB", "VulnCheck"])).to_numpy())]
    for name, m in groups:
        idx = np.flatnonzero(m)
        base31 = np.bincount(b31t[idx]).max() / len(idx)
        acc31 = (b31t[idx] == b31p[idx]).mean()
        k31 = cohen_kappa_score(b31t[idx], b31p[idx])
        f31 = macro_f1(t31.iloc[idx], p31.iloc[idx], V31_METRICS)
        tb, pb = e_t.band[idx], e_p.band[idx]
        base40 = np.bincount(tb[tb >= 0]).max() / len(idx)
        acc40 = (tb == pb).mean()
        k40 = cohen_kappa_score(tb, pb)
        f40 = macro_f1(t40.iloc[idx], p40.iloc[idx], V40_METRICS)
        lines.append(f"| {name} | {len(idx):,} | {base31:.3f} / {acc31:.3f} / {k31:.3f} / {f31:.3f} | {base40:.3f} / {acc40:.3f} / {k40:.3f} / {f40:.3f} |")
    lines.append("\n(Macro-F1 is averaged over all values of each metric; values that do not occur score 0, as in the paper.)")


def part_b(test, lines):
    yr = test["cve_id"].str.extract(r"CVE-(\d{4})-")[0].astype(int)
    lines += ["\n## B. CVE identifier years in the temporal split test set (published in 2026)\n", "| Source | n | Identifier year < 2025 | Identifier year = 2025 | Identifier year = 2026 |", "|---|---|---|---|---|"]
    for name, m in [("VulnCheck", test["source"] == "VulnCheck"), ("VulDB", test["source"] == "VulDB"), ("GitHub_M", test["source"] == "GitHub_M"),
                    ("other sources", ~test["source"].isin(["VulnCheck", "VulDB", "GitHub_M"])), ("all", pd.Series(True, index=test.index))]:
        y = yr[m]
        lines.append(f"| {name} | {int(m.sum()):,} | {(y < 2025).mean():.1%} | {(y == 2025).mean():.1%} | {(y == 2026).mean():.1%} |")


def part_c(test, lines):
    ids = test["cve_id"]
    t = Encoded(test, "y_")

    def enc(path):
        return Encoded(pd.read_parquet(path).set_index("cve_id").loc[ids].reset_index())
    methods = {"majority class": [enc(ROOT / "results" / "baselines_v0" / "predictions" / "T2_temporal_majority.parquet")],
               "TF-IDF + LR": [enc(ROOT / "results" / "baselines_v0" / "predictions" / "T2_temporal_tfidf_lr.parquet")],
               "DeBERTa (25 epochs)": [enc(ENC / f"T2_temporal_deberta-v3-base_none_e25_cwinv_sqrt_s{s}" / "pred_latent.parquet") for s in range(5)],
               "DeBERTa + auxiliary": [enc(ENC / f"T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s{s}" / "pred_latent.parquet") for s in range(5)]}
    src = test["source"].to_numpy()
    counts = test["source"].value_counts()
    lines.append("\n## C. Source-macro averages (temporal split test set; equal weight per source)\n")
    for min_n in (30, 100):
        keep = [s for s, n in counts.items() if n >= min_n]
        per = {m: {} for m in methods}
        for s in keep:
            idx = np.flatnonzero(src == s)
            for m, es in methods.items():
                rs = [fast_scores(t, e, idx) for e in es]
                per[m][s] = {k: np.mean([r[k] for r in rs]) for k in ("mean_macro_f1", "band_acc", "under_rate")}
        n_cve = int(sum(counts[s] for s in keep))
        lines += [f"\nSources with at least {min_n} test CVEs: {len(keep)} (covering {n_cve:,} / {len(test):,} CVEs)\n", "| Method | Mean macro-F1 | Band accuracy | Underestimation |", "|---|---|---|---|"]
        for m in methods:
            lines.append(f"| {m} | " + " | ".join(f"{np.mean([per[m][s][k] for s in keep]):.3f}" for k in ("mean_macro_f1", "band_acc", "under_rate")) + " |")
        d = np.array([per["DeBERTa + auxiliary"][s]["mean_macro_f1"] - per["DeBERTa (25 epochs)"][s]["mean_macro_f1"] for s in keep])
        db = np.array([per["DeBERTa + auxiliary"][s]["band_acc"] - per["DeBERTa (25 epochs)"][s]["band_acc"] for s in keep])
        bs = np.array([[d[i].mean(), db[i].mean()] for i in (rng.integers(len(keep), size=len(keep)) for _ in range(2000))])
        lines.append(f"\nAuxiliary − DeBERTa (25 epochs), source-macro average: mean macro-F1 {d.mean():+.3f} [{np.percentile(bs[:, 0], 2.5):+.3f}, {np.percentile(bs[:, 0], 97.5):+.3f}]"
                     f" (sources resampled); sources where the auxiliary model is better {int((d > 0).sum())} / {len(keep)}; band accuracy {db.mean():+.3f} [{np.percentile(bs[:, 1], 2.5):+.3f}, {np.percentile(bs[:, 1], 97.5):+.3f}]. ")
        dt = np.array([per["DeBERTa + auxiliary"][s]["mean_macro_f1"] - per["TF-IDF + LR"][s]["mean_macro_f1"] for s in keep])
        lines.append(f"Auxiliary − TF-IDF, source-macro average: mean macro-F1 {dt.mean():+.3f}; sources where the auxiliary model is better {int((dt > 0).sum())} / {len(keep)}.")


def part_e(test, lines):
    ids = test["cve_id"]
    t = Encoded(test, "y_")

    def enc(path):
        return Encoded(pd.read_parquet(path).set_index("cve_id").loc[ids].reset_index())
    es = {"TF-IDF + LR": [enc(ROOT / "results" / "baselines_v0" / "predictions" / "T2_temporal_tfidf_lr.parquet")],
          "DeBERTa (25 epochs)": [enc(ENC / f"T2_temporal_deberta-v3-base_none_e25_cwinv_sqrt_s{s}" / "pred_latent.parquet") for s in range(5)],
          "DeBERTa + auxiliary": [enc(ENC / f"T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s{s}" / "pred_latent.parquet") for s in range(5)]}
    old = (test["cve_id"].str.extract(r"CVE-(\d{4})-")[0].astype(int) < 2025).to_numpy()
    nd = (test["label_type"] != "derived").to_numpy()
    lines += ["\n## E. Main results without the back-filled test CVEs (identifier year before 2025)\n",
              f"Removed: {int(old.sum()):,} (VulnCheck {int((old & (test['source'] == 'VulnCheck').to_numpy()).sum()):,}). Mean macro-F1 / band accuracy:\n",
              "| Scope | n | TF-IDF + LR | DeBERTa (25 epochs) | DeBERTa + auxiliary | Auxiliary − DeBERTa (macro-F1) [95%] |", "|---|---|---|---|---|---|"]
    for name, m in [("all test labels", np.ones(len(test), bool)), ("all, without back-filled", ~old), ("non-derived", nd), ("non-derived, without back-filled", nd & ~old),
                    ("VulnCheck", (test["source"] == "VulnCheck").to_numpy()), ("VulnCheck, without back-filled", (test["source"] == "VulnCheck").to_numpy() & ~old),
                    ("VulnCheck, back-filled only", (test["source"] == "VulnCheck").to_numpy() & old)]:
        idx = np.flatnonzero(m)

        def f(ix, k, key="mean_macro_f1"):
            return np.mean([fast_scores(t, e, ix)[key] for e in es[k]])
        cells = [f"{f(idx, k):.3f} / {f(idx, k, 'band_acc'):.3f}" for k in es]
        bs = [f(ix, "DeBERTa + auxiliary") - f(ix, "DeBERTa (25 epochs)") for ix in (rng.choice(idx, size=len(idx), replace=True) for _ in range(1000))]
        d = f(idx, "DeBERTa + auxiliary") - f(idx, "DeBERTa (25 epochs)")
        lines.append(f"| {name} | {len(idx):,} | " + " | ".join(cells) + f" | {d:+.3f} [{np.percentile(bs, 2.5):+.3f}, {np.percentile(bs, 97.5):+.3f}] |")


def part_d(df, lines):
    te = df[(df["pub"] >= CUTOFF) & df["has_v31"]]
    lines += ["\n## D. Label types of the T1 test set (2026, dual-scored)\n", "; ".join(f"{k} {v:,}" for k, v in te["label_type"].value_counts().items()) + f"; total {len(te):,}.",
              "By definition, fewer than 5% of the CVEs of v4-only CNAs are dual-scored; their dual-scored CVEs in 2026: "
              + f"{int((te['label_type'] == 'v4_only').sum())} (" + ", ".join(f"{s} {n}" for s, n in te.loc[te['label_type'] == 'v4_only', 'source'].value_counts().items()) + ")."]


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    lines = ["# Predictability by source, back-filling and source-macro averages (generated automatically)\n"]
    for step in (lambda: part_a(df, lines), lambda: part_b(test, lines), lambda: part_c(test, lines), lambda: part_d(df, lines), lambda: part_e(test, lines)):
        step()
        OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
