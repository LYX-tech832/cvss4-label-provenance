"""Two checks (CPU).

A. Do the TF-IDF settings affect the ranking reversal between the classifier and the pipeline (temporal split, T2)? The paper's C = 4
   of TF-IDF + LR and the two feature settings (classifier: minimum document frequency 2, at most 200,000 features; first stage of the
   pipeline: 3 and 300,000) were fixed at the start and not tuned. This script:
   - classifier with C in {0.25, 1, 4, 16, 64, 256} (the grid extends two steps above 16 because the validation optimum lay at 16 on a
     smaller grid): mean macro-F1 on the validation set (the latest 10% of the training data), then retrained on all training labels and
     evaluated on the test set;
   - first stage of the pipeline with C in {1, 4, 16}: mean macro-F1 of v3.1 on the latest 10% of the v3.1 corpus, then retrained on the
     whole corpus;
   - each side run once with the other side's feature setting (C = 4);
   - on the LLM sample (2,000 CVEs), the mean macro-F1 difference between DeepSeek-V4-Pro and the classifier at each C (the reversal in
     Section 7.5);
   - the band accuracy difference "classifier − pipeline" for each combination (all / non-derived), and paired bootstrap intervals for
     the combination selected on each side's validation set.
   The predictions of each configuration are cached in results/tfidf_sensitivity/, so the runs can be split. About 1-1.5 hours.
B. Additional row of Table S14: the auxiliary-task model with seeds 0-2 only (the differences in Note S6 use 3 seeds). Seconds.
Output: results/review_checks/summary16.md
Usage: python src/review_checks10.py [a|b|all]
"""

import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded, fast_scores  # noqa: E402
from baselines_v0 import CUTOFF, M31, M40, SEED, evaluate, load, source_type_map  # noqa: E402
from cvss_utils import V31_METRICS  # noqa: E402
from pilot_transfer import v31_pool  # noqa: E402
from pipeline_baseline import convert  # noqa: E402
from review_checks import clean_mask  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
CACHE = ROOT / "results" / "tfidf_sensitivity"
OUT = ROOT / "results" / "review_checks" / "summary16.md"
C_CLF, C_PIPE = [0.25, 1.0, 4.0, 16.0, 64.0, 256.0], [1.0, 4.0, 16.0]
F_CLF, F_PIPE = (2, 200_000), (3, 300_000)


def fit_predict(train_text, ys, queries, C, feat):
    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=feat[0], max_features=feat[1], sublinear_tf=True)
    x = vec.fit_transform(train_text)
    xq = [vec.transform(q) for q in queries]
    out = [{} for _ in queries]
    for k, y in ys.items():
        if len(set(y)) == 1:
            for o, q in zip(out, xq):
                o[k] = [y[0]] * q.shape[0]
            continue
        clf = LogisticRegression(C=C, max_iter=3000, random_state=SEED).fit(x, y)
        for o, q in zip(out, xq):
            o[k] = clf.predict(q)
    return [pd.DataFrame(o) for o in out]


def cached(name, fn):
    """fn() returns (test predictions, validation score); the result is cached."""
    f, g = CACHE / f"{name}.parquet", CACHE / f"{name}.json"
    if f.exists() and g.exists():
        return pd.read_parquet(f), json.loads(g.read_text())["val"]
    t0 = time.time()
    pred, val = fn()
    pred.to_parquet(f, index=False)
    g.write_text(json.dumps({"val": val, "seconds": round(time.time() - t0)}))
    print(f"  {name}: validation {val}, {time.time() - t0:.0f} s", flush=True)
    return pred, val


def part_a(lines):
    CACHE.mkdir(parents=True, exist_ok=True)
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    train, test = df[df["pub"] < CUTOFF], df[df["pub"] >= CUTOFF].reset_index(drop=True)
    order = train.sort_values("pub", kind="stable")
    n_val = int(0.1 * len(order))
    fit, val = order.iloc[:-n_val], order.iloc[-n_val:].reset_index(drop=True)
    tv = Encoded(val, "y_")

    def clf(C, feat):
        def run():
            ys = lambda d: {k: d["y_" + k].values for k in M40}  # noqa: E731
            pv = fit_predict(fit["text"], ys(fit), [val["text"]], C, feat)[0]
            v = fast_scores(tv, Encoded(pv), np.arange(len(val)))["mean_macro_f1"]
            pt = fit_predict(train["text"], ys(train), [test["text"]], C, feat)[0]
            return pt.assign(cve_id=test["cve_id"].values), round(v, 4)
        return cached(f"clf_C{C}_df{feat[0]}", run)

    pool = v31_pool(before_cutoff=True)
    porder = pool.sort_values("pub", kind="stable")
    pn = int(0.1 * len(porder))
    pfit, pval = porder.iloc[:-pn], porder.iloc[-pn:]

    def pipe(C, feat):
        def run():
            ys = lambda d: {k: d["z_" + k].values for k in M31}  # noqa: E731
            pv = fit_predict(pfit["text"], ys(pfit), [pval["text"]], C, feat)[0]
            v = float(np.mean([f1_score(pval["z_" + k].values, pv[k].values, labels=V31_METRICS[k], average="macro", zero_division=0) for k in M31]))
            p31 = fit_predict(pool["text"], ys(pool), [test["text"]], C, feat)[0]
            return convert(p31, True).assign(cve_id=test["cve_id"].values), round(v, 4)
        return cached(f"pipe_C{C}_df{feat[0]}", run)

    print(f"A: classifier training {len(train):,} (validation {n_val:,}), corpus {len(pool):,} (validation {pn:,}), test {len(test):,}", flush=True)
    clfs = {C: clf(C, F_CLF) for C in C_CLF}
    clf_swap = clf(4.0, F_PIPE)
    pipes = {C: pipe(C, F_PIPE) for C in C_PIPE}
    pipe_swap = pipe(4.0, F_CLF)

    t = Encoded(test, "y_")
    alli, ndi = np.arange(len(test)), np.flatnonzero((test["label_type"] != "derived").to_numpy())
    enc = lambda p: Encoded(p.set_index("cve_id").loc[test["cve_id"]].reset_index())  # noqa: E731
    ec = {C: enc(p) for C, (p, _) in clfs.items()}
    ep = {C: enc(p) for C, (p, _) in pipes.items()}
    sc = lambda e: (fast_scores(t, e, alli), fast_scores(t, e, ndi))  # noqa: E731
    lines += ["## A. TF-IDF settings and the ranking reversal (temporal split; 21,900 test labels, 16,749 non-derived)\n",
              f"The classifier is trained on {len(fit):,} and validated on {n_val:,} CVEs, then retrained on all {len(train):,}; the first stage of the pipeline is trained on {len(pfit):,} and validated on {pn:,} CVEs of the v3.1 corpus, then retrained on all {len(pool):,}.\n",
              "### Classifier (TF-IDF + LR, v4.0 labels; minimum document frequency 2, at most 200,000 features)\n",
              "| C | Mean validation macro-F1 | Test: mean macro-F1 all / non-derived | Test: band accuracy all / non-derived |", "|---|---|---|---|"]
    for C, (p, v) in clfs.items():
        a, b = sc(ec[C])
        lines.append(f"| {C:g}{' (paper)' if C == 4.0 else ''} | {v:.4f} | {a['mean_macro_f1']:.3f} / {b['mean_macro_f1']:.3f} | {a['band_acc']:.3f} / {b['band_acc']:.3f} |")
    lines += ["\n### Pipeline (first stage TF-IDF + LR predicts v3.1, then conversion with rule R; minimum document frequency 3, at most 300,000 features)\n",
              "| C | Validation: v3.1 mean macro-F1 | Test: mean macro-F1 all / non-derived | Test: band accuracy all / non-derived |", "|---|---|---|---|"]
    for C, (p, v) in pipes.items():
        a, b = sc(ep[C])
        lines.append(f"| {C:g}{' (paper)' if C == 4.0 else ''} | {v:.4f} | {a['mean_macro_f1']:.3f} / {b['mean_macro_f1']:.3f} | {a['band_acc']:.3f} / {b['band_acc']:.3f} |")
    lines += ["\n### Band accuracy difference: classifier − pipeline, all / non-derived\n", "| Classifier C vs pipeline C | " + " | ".join(f"{c:g}" for c in C_PIPE) + " |", "|---|" + "---|" * len(C_PIPE)]
    da, dn = [], []
    for cc in C_CLF:
        cells = []
        for cp in C_PIPE:
            a = (t.band == ec[cc].band).mean() - (t.band == ep[cp].band).mean()
            n = (t.band[ndi] == ec[cc].band[ndi]).mean() - (t.band[ndi] == ep[cp].band[ndi]).mean()
            da.append(a)
            dn.append(n)
            cells.append(f"{a:+.3f} / {n:+.3f}")
        lines.append(f"| {cc:g} | " + " | ".join(cells) + " |")
    lines.append(f"\nOver the {len(da)} combinations: the difference on all labels ranges from {min(da):+.3f} to {max(da):+.3f}, on the non-derived labels from {min(dn):+.3f} to {max(dn):+.3f}; "
                 f"positive on all labels in {sum(x > 0 for x in da)}, negative on the non-derived labels in {sum(x < 0 for x in dn)}.")
    bc = max(clfs, key=lambda c: clfs[c][1])
    bp = max(pipes, key=lambda c: pipes[c][1])
    rng = np.random.default_rng(0)
    hit_c, hit_p = (t.band == ec[bc].band).astype(float), (t.band == ep[bp].band).astype(float)
    res = []
    for idx in (alli, ndi):
        d = hit_c[idx] - hit_p[idx]
        bs = [d[rng.integers(len(d), size=len(d))].mean() for _ in range(1000)]
        res.append(f"{d.mean():+.3f} [{np.percentile(bs, 2.5):+.3f}, {np.percentile(bs, 97.5):+.3f}]")
    lines.append(f"\nSettings selected on each side's validation set (classifier C = {bc:g}, pipeline C = {bp:g}): band accuracy difference all {res[0]}, non-derived {res[1]} (paired bootstrap, 1,000 resamples). "
                 f"Mean macro-F1 difference: all {sc(ec[bc])[0]['mean_macro_f1'] - sc(ep[bp])[0]['mean_macro_f1']:+.3f}, non-derived {sc(ec[bc])[1]['mean_macro_f1'] - sc(ep[bp])[1]['mean_macro_f1']:+.3f}.")
    llm = pd.read_parquet(ROOT / "results" / "autocvss_baseline" / "deepseek-v4-pro_DTD_s0" / "predictions.parquet")
    samp = df.set_index("cve_id").loc[llm["cve_id"]].reset_index()
    ts, el = Encoded(samp, "y_"), Encoded(llm)
    lt = samp["label_type"].to_numpy()
    strata = [np.flatnonzero(lt == x) for x in ["derived", "independent", "v4_only", "other"]]
    rng2 = np.random.default_rng(0)
    lines += ["\n### LLM sample (2,000 CVEs): mean macro-F1 DeepSeek-V4-Pro − classifier (paired bootstrap stratified by label type, 1,000 resamples)\n",
              "| Classifier C | Whole sample | Non-derived (1,700) |", "|---|---|---|"]
    for C, (p, _) in clfs.items():
        es = Encoded(p.set_index("cve_id").loc[llm["cve_id"]].reset_index())

        def d(ix):
            nd = ix[lt[ix] != "derived"]
            return (fast_scores(ts, el, ix)["mean_macro_f1"] - fast_scores(ts, es, ix)["mean_macro_f1"],
                    fast_scores(ts, el, nd)["mean_macro_f1"] - fast_scores(ts, es, nd)["mean_macro_f1"])
        pt = d(np.arange(len(samp)))
        bs = np.array([d(np.concatenate([rng2.choice(x, size=len(x), replace=True) for x in strata])) for _ in range(1000)])
        lines.append(f"| {C:g}{' (paper)' if C == 4.0 else ''} | {pt[0]:+.3f} [{np.percentile(bs[:, 0], 2.5):+.3f}, {np.percentile(bs[:, 0], 97.5):+.3f}] | "
                     f"{pt[1]:+.3f} [{np.percentile(bs[:, 1], 2.5):+.3f}, {np.percentile(bs[:, 1], 97.5):+.3f}] |")
    lines += ["\n### Feature settings swapped (C = 4)\n", "| Setting | Test: band accuracy all / non-derived | Classifier − pipeline (all / non-derived) |", "|---|---|---|"]
    es, ps = enc(clf_swap[0]), enc(pipe_swap[0])
    band = lambda e: ((t.band == e.band).mean(), (t.band[ndi] == e.band[ndi]).mean())  # noqa: E731
    for name, ce, pe in [("paper's settings (classifier 2 / 200,000, pipeline 3 / 300,000)", ec[4.0], ep[4.0]), ("classifier with 3 / 300,000", es, ep[4.0]), ("pipeline with 2 / 200,000", ec[4.0], ps), ("both swapped", es, ps)]:
        (ca, cn), (pa, pn_) = band(ce), band(pe)
        lines.append(f"| {name} | classifier {ca:.3f} / {cn:.3f}; pipeline {pa:.3f} / {pn_:.3f} | {ca - pa:+.3f} / {cn - pn_:+.3f} |")


def part_b(lines):
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    clean = clean_mask(test).to_numpy() if hasattr(clean_mask(test), "to_numpy") else np.asarray(clean_mask(test))
    subsets = {"R-inc.": clean, "No v3.1": (~test["has_v31"]).to_numpy(), "R-inc., no VulnCheck": clean & (test["source"] != "VulnCheck").to_numpy()}
    atp = clean & (test["y_AT"] == "P").to_numpy()
    lines += ["\n## B. Additional row of Table S14: the auxiliary-task model (5 epochs), 5 seeds and seeds 0–2\n",
              "| Seeds | " + " | ".join(f"{k} ({int(m.sum()):,})" for k, m in subsets.items()) + " | AT:P predicted as None | AT macro-F1 (R-inc.) |", "|---|---|---|---|---|---|"]
    for name, seeds in [("0–4 (the row already in the table)", range(5)), ("0–2", range(3))]:
        ps = [pd.read_parquet(ENC / f"T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s{s}" / "pred_latent.parquet").set_index("cve_id").loc[test["cve_id"]].reset_index() for s in seeds]
        cells = []
        for m in subsets.values():
            idx = np.flatnonzero(m)
            rs = [evaluate(test.iloc[idx].reset_index(drop=True), p.iloc[idx].reset_index(drop=True)) for p in ps]
            cells.append(f"{np.mean([r['mean_macro_f1'] for r in rs]):.3f} / {np.mean([r['band_acc'] for r in rs]):.3f}")
        idx = np.flatnonzero(clean)
        at = np.mean([evaluate(test.iloc[idx].reset_index(drop=True), p.iloc[idx].reset_index(drop=True))["per_metric"]["AT"]["macro_f1"] for p in ps])
        share = np.mean([(p["AT"].to_numpy()[atp] == "N").mean() for p in ps])
        lines.append(f"| {name} | " + " | ".join(cells) + f" | {share:.3f} | {at:.3f} |")


def main():
    part = sys.argv[1] if len(sys.argv) > 1 else "all"
    lines = ["# Sensitivity to the TF-IDF settings; three-seed row of Table S14 (generated automatically)\n"]
    if part in ("a", "all"):
        part_a(lines)
    if part in ("b", "all"):
        part_b(lines)
    if part == "all":
        OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"written to {OUT}")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
