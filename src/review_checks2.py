"""Robustness checks, second set (CPU, about 10-20 minutes).

A. Unrounded differences of the auxiliary-task gain, and two intervals that include training randomness: a seed-level t interval
   (paired by seed number) and a two-level bootstrap that resamples CVEs and seeds together (in each resample, 5 seeds drawn with
   replacement for each variant).
B. LLM comparison weighted by the true composition of the test set (each bootstrap draws 2,000 CVEs from the label types in their true
   proportions).
C. Per-metric inflation: macro-F1 on all vs non-derived vs R-inconsistent labels (dual-scored and v4 ≠ rule R(v3.1)).
D. Near-duplicates: maximum TF-IDF cosine similarity between test descriptions and training descriptions (v4 training set, v3.1 pool);
   severity wording in VulDB's descriptions.
E. Update time of the CNA container (closer to "when the v4 vector was written" than the record-level update time): share of CVEs
   published before 2026 whose CNA container was updated after the start of 2026; whether the typing changes without these CVEs; how much
   the TF-IDF baseline's test results change without these training samples.
F. Synthetic conversion convention: v4 labels replaced by a conversion that is deterministic but differs from rule R, to see what the
   rule-R agreement and FD_oos report.
Output: results/review_checks/summary2.md
"""

import json
import re
import sys
import zipfile
from collections import Counter
from pathlib import Path

import numpy as np
import orjson
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded, fast_scores  # noqa: E402
from baselines_v0 import CUTOFF, M31, M40, evaluate, load, pred_tfidf_lr, source_type_map  # noqa: E402
from label_provenance import THRESHOLD, analyse, collect  # noqa: E402
from pilot_transfer import v31_pool  # noqa: E402
from review_checks import clean_mask, fd_variants  # noqa: E402
from rq1_stats import rule_convert  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "review_checks"
ENC = ROOT / "results" / "encoder"
LLM = ROOT / "results" / "autocvss_baseline" / "deepseek-v4-pro_DTD_s0"
PRED = ROOT / "results" / "baselines_v0" / "predictions"
SPLITS = ["temporal", "loso-VulnCheck", "loso-GitHub_M", "loso-VulDB"]
T4 = 2.776  # t 分布 0.975 分位，自由度 4


def runs(split, aux):
    return [ENC / f"T2_{split}_deberta-v3-base_none{'_aux' if aux else ''}_e5_cwinv_sqrt_s{s}" for s in range(5)]


def enc_preds(dirs, ids):
    return [Encoded(pd.read_parquet(d / "pred_latent.parquet").set_index("cve_id").loc[ids].reset_index()) for d in dirs]


def part_a(df, lines, rng):
    lines += ["\n## A. Auxiliary-task gain: unrounded differences and intervals including training randomness (mean macro-F1)\n",
              "| Split | Scope | Difference (unrounded) | Difference per seed | Seed t interval (paired, df=4) | Two-level bootstrap interval (CVE × seed) |", "|---|---|---|---|---|---|"]
    for split in SPLITS:
        ids = pd.read_parquet(runs(split, False)[0] / "pred_latent.parquet")["cve_id"]
        truth = df.set_index("cve_id").loc[ids].reset_index()
        t = Encoded(truth, "y_")
        pn, pa = enc_preds(runs(split, False), ids), enc_preds(runs(split, True), ids)
        scopes = [("all", np.arange(len(truth)))]
        if split == "temporal":
            scopes.append(("non-derived", np.flatnonzero(truth["label_type"].to_numpy() != "derived")))
        for name, pool in scopes:
            fa = np.array([fast_scores(t, p, pool)["mean_macro_f1"] for p in pa])
            fn = np.array([fast_scores(t, p, pool)["mean_macro_f1"] for p in pn])
            d = fa - fn
            m, sd = d.mean(), d.std(ddof=1)
            boots = []
            for _ in range(1000):
                idx = rng.choice(pool, size=len(pool), replace=True)
                sa, sn = rng.integers(0, 5, 5), rng.integers(0, 5, 5)
                boots.append(np.mean([fast_scores(t, pa[i], idx)["mean_macro_f1"] for i in sa]) -
                             np.mean([fast_scores(t, pn[i], idx)["mean_macro_f1"] for i in sn]))
            lo, hi = np.percentile(boots, [2.5, 97.5])
            lines.append(f"| {split} | {name} | {m:+.4f} | " + ", ".join(f"{x:+.3f}" for x in d) +
                         f" | [{m - T4 * sd / np.sqrt(5):+.3f}, {m + T4 * sd / np.sqrt(5):+.3f}] | [{lo:+.3f}, {hi:+.3f}] |")


def part_b(df, lines, rng):
    llm = pd.read_parquet(LLM / "predictions.parquet")
    ids = llm["cve_id"]
    s = df.set_index("cve_id").loc[ids].reset_index()
    raw = [json.loads(x) for x in (LLM / "raw.jsonl").read_text(encoding="utf-8").splitlines()]
    unknown = {(r["cve_id"], r["metric"]) for r in raw if r["label"] in (None, "DONT_KNOW")}
    train = df[df["pub"] < CUTOFF]
    alt = llm.set_index("cve_id").loc[ids].reset_index()
    pos = {c: i for i, c in enumerate(alt["cve_id"])}
    for cve, k in unknown:
        alt.iloc[pos[cve], alt.columns.get_loc(k)] = train["y_" + k].mode()[0]
    t = Encoded(s, "y_")
    meth = {"DeepSeek (as in AutoCVSS)": [Encoded(llm.set_index("cve_id").loc[ids].reset_index())],
            "DeepSeek (DONT_KNOW → most frequent)": [Encoded(alt)],
            "TF-IDF": [Encoded(pd.read_parquet(PRED / "T2_temporal_tfidf_lr.parquet").set_index("cve_id").loc[ids].reset_index())],
            "DeBERTa + auxiliary": enc_preds(runs("temporal", True), ids)}
    test = df[df["pub"] >= CUTOFF]
    comp = test["label_type"].value_counts()
    lt = s["label_type"].to_numpy()
    lines += ["\n## B. LLM comparison weighted by the true composition of the test set (each bootstrap draws 2,000 CVEs from the label types in their true proportions, 1,000 times; mean and 95% interval)\n",
              "Composition of the test set: " + ", ".join(f"{k} {v:,} ({v / len(test):.1%})" for k, v in comp.items()) + "\n",
              "| Scope | Method | Mean macro-F1 | Band accuracy | Macro-F1 difference from TF-IDF | Band accuracy difference |", "|---|---|---|---|---|---|"]
    for scope, types in [("weighted, all", ["derived", "independent", "v4_only", "other"]), ("weighted, non-derived", ["independent", "v4_only", "other"])]:
        w = comp[types] / comp[types].sum()
        sizes = {ty: int(round(2000 * w[ty])) for ty in types}
        strata = {ty: np.flatnonzero(lt == ty) for ty in types}
        res = {n: [] for n in meth}
        for _ in range(1000):
            b = np.concatenate([rng.choice(strata[ty], size=sizes[ty], replace=True) for ty in types])
            for n, ps in meth.items():
                sc = [fast_scores(t, p, b) for p in ps]
                res[n].append((np.mean([x["mean_macro_f1"] for x in sc]), np.mean([x["band_acc"] for x in sc])))
        base = np.array(res["TF-IDF"])
        for n in meth:
            a = np.array(res[n])
            d = a - base
            cell = "—" if n == "TF-IDF" else (f"{d[:, 0].mean():+.3f} [{np.percentile(d[:, 0], 2.5):+.3f}, {np.percentile(d[:, 0], 97.5):+.3f}] | "
                                              f"{d[:, 1].mean():+.3f} [{np.percentile(d[:, 1], 2.5):+.3f}, {np.percentile(d[:, 1], 97.5):+.3f}]")
            lines.append(f"| {scope} | {n} | {a[:, 0].mean():.3f} | {a[:, 1].mean():.3f} | {cell if n != 'TF-IDF' else '— | —'} |")


def per_metric(t, p):
    r = evaluate(t.reset_index(drop=True), p.reset_index(drop=True))
    return {k: r["per_metric"][k]["macro_f1"] for k in M40}


def part_c(test, lines):
    tf = pd.read_parquet(PRED / "T2_temporal_tfidf_lr.parquet").set_index("cve_id").loc[test["cve_id"]].reset_index()
    maj = pd.read_parquet(PRED / "T2_temporal_majority.parquet").set_index("cve_id").loc[test["cve_id"]].reset_index()
    ds = {v: [pd.read_parquet(d / "pred_latent.parquet").set_index("cve_id").loc[test["cve_id"]].reset_index() for d in runs("temporal", v)]
          for v in (False, True)}
    masks = {"all": np.ones(len(test), bool), "non-derived": (test["label_type"] != "derived").to_numpy(), "R-inconsistent subset": test["clean"].to_numpy()}
    lines += ["\n## C. Per-metric macro-F1 (temporal split test set; DeBERTa averaged over 5 seeds)\n",
              "| Metric | Majority all / non-derived | TF-IDF all / non-derived / R-inconsistent | DeBERTa all / non-derived | DeBERTa+auxiliary all / non-derived / R-inconsistent | TF-IDF inflation (all − non-derived) | DeBERTa+auxiliary inflation |",
              "|---|---|---|---|---|---|---|"]
    res = {}
    for name, m in masks.items():
        tt = test[m]
        res[("maj", name)] = per_metric(tt, maj[m])
        res[("tf", name)] = per_metric(tt, tf[m])
        for v in (False, True):
            pm = [per_metric(tt, p[m]) for p in ds[v]]
            res[(v, name)] = {k: np.mean([x[k] for x in pm]) for k in M40}
    for k in M40:
        lines.append(f"| {k} | {res[('maj', 'all')][k]:.3f} / {res[('maj', 'non-derived')][k]:.3f} | "
                     f"{res[('tf', 'all')][k]:.3f} / {res[('tf', 'non-derived')][k]:.3f} / {res[('tf', 'R-inconsistent subset')][k]:.3f} | "
                     f"{res[(False, 'all')][k]:.3f} / {res[(False, 'non-derived')][k]:.3f} | "
                     f"{res[(True, 'all')][k]:.3f} / {res[(True, 'non-derived')][k]:.3f} / {res[(True, 'R-inconsistent subset')][k]:.3f} | "
                     f"{res[('tf', 'all')][k] - res[('tf', 'non-derived')][k]:+.3f} | {res[(True, 'all')][k] - res[(True, 'non-derived')][k]:+.3f} |")
    return tf, ds


def max_sim(query, refs, chunk=500):
    vec = TfidfVectorizer(ngram_range=(1, 1), min_df=2, sublinear_tf=True).fit(list(refs) + list(query))
    r, q = vec.transform(refs).T.tocsc(), vec.transform(query)
    out = np.zeros(q.shape[0])
    for i in range(0, q.shape[0], chunk):
        out[i:i + chunk] = (q[i:i + chunk] @ r).max(axis=1).toarray().ravel()
    return out


def part_d(df, test, tf, ds, lines):
    train = df[df["pub"] < CUTOFF]
    pool = v31_pool(before_cutoff=True)
    s_tr = max_sim(test["description"].str.strip(), train["description"].str.strip())
    s_pool = max_sim(test["description"].str.strip(), pool["description"].str.strip())
    lines += ["\n## D. Near-duplicates (maximum cosine similarity of TF-IDF term vectors; ≥ 0.9 counts as a near-duplicate)\n",
              "| Label type | n | Near-duplicate of a v4 training description | Near-duplicate in the v3.1 pool | Median similarity (v4 training) |", "|---|---|---|---|---|"]
    for ty in ["derived", "independent", "v4_only", "other"]:
        m = (test["label_type"] == ty).to_numpy()
        lines.append(f"| {ty} | {m.sum():,} | {(s_tr[m] >= 0.9).mean():.1%} | {(s_pool[m] >= 0.9).mean():.1%} | {np.median(s_tr[m]):.2f} |")
    nd = s_tr < 0.9
    lines.append("\nWithout the test CVEs that are near-duplicates of v4 training descriptions (band accuracy; DeBERTa+auxiliary averaged over 5 seeds):")
    for name, m in [("derived", (test["label_type"] == "derived").to_numpy()), ("non-derived", (test["label_type"] != "derived").to_numpy())]:
        for sub, mm in [("all", m), ("without near-duplicates", m & nd)]:
            b_tf = evaluate(test[mm].reset_index(drop=True), tf[mm].reset_index(drop=True))["band_acc"]
            b_ds = np.mean([evaluate(test[mm].reset_index(drop=True), p[mm].reset_index(drop=True))["band_acc"] for p in ds[True]])
            lines.append(f"- {name}, {sub} (n = {mm.sum():,}): TF-IDF {b_tf:.3f}, DeBERTa+auxiliary {b_ds:.3f}")
    vul = df[df["source"] == "VulDB"]
    cls = vul["description"].str.extract(r"(?:classified|rated) as (critical|problematic|very critical|uncritical)", flags=re.I)[0].str.lower()
    lines.append(f"\nVulDB descriptions containing \"classified/rated as <severity>\": {cls.notna().mean():.1%} ({int(cls.notna().sum()):,} / {len(vul):,}); cross-table of the wordings and the v4.0 severity bands (all of VulDB's v4 labels):\n")
    band = vul.apply(lambda r: __import__("baselines_v0").v4_score("CVSS:4.0/" + "/".join(f"{k}:{r['y_' + k]}" for k in M40))[1], axis=1)
    ct = pd.crosstab(cls.fillna("—"), band)
    lines.append("| Wording | " + " | ".join(ct.columns) + " |")
    lines.append("|---|" + "---|" * len(ct.columns))
    for w, row in ct.iterrows():
        lines.append(f"| {w} | " + " | ".join(f"{v:,}" for v in row) + " |")
    other = df[df["source"] != "VulDB"]["description"].str.contains(r"classified as (?:critical|problematic)", case=False).mean()
    lines.append(f"\nShare of descriptions of other sources with the same wording: {other:.2%}")


def cna_updated(ids):
    want = set(ids)
    out = {}
    with zipfile.ZipFile(ROOT / "data" / "raw" / "cves.zip") as z:
        for n in z.namelist():
            base = n.rsplit("/", 1)[-1][:-5] if n.endswith(".json") else None
            if base in want:
                rec = orjson.loads(z.read(n))
                out[base] = ((rec.get("containers") or {}).get("cna") or {}).get("providerMetadata", {}).get("dateUpdated")
    return pd.Series(out)


def part_e(df, lines):
    upd = pd.to_datetime(cna_updated(df["cve_id"]), utc=True, errors="coerce", format="mixed")
    df = df.assign(cna_upd=df["cve_id"].map(upd))
    pre = df["pub"] < CUTOFF
    late = df["cna_upd"] >= CUTOFF
    lines += ["\n## E. Update time of the CNA container (providerMetadata.dateUpdated; any change of the CNA to its container updates it, so it is still an upper bound)\n",
              f"- Without an update time of the CNA container: {int(df['cna_upd'].isna().sum())}; ",
              f"- of the {int(pre.sum()):,} v4 samples published before 2026, {int((pre & late).sum()):,} have a CNA container updated after the start of 2026 ({(pre & late).sum() / pre.sum():.1%}); ",
              f"- of the {int((pre & df['has_v31']).sum()):,} dual-scored ones, {int((pre & late & df['has_v31']).sum()):,} ({(pre & late & df['has_v31']).sum() / (pre & df['has_v31']).sum():.1%}); ",
              "- by source (at least 500 v4 samples in the training part): " + "; ".join(
                  f"{s} {g['mean']:.1%} ({int(g['size']):,})" for s, g in df[pre].assign(late=late[pre]).groupby("source")["late"].agg(["mean", "size"]).query("size >= 500").sort_values("mean", ascending=False).iterrows())]
    # 分型：去掉可能在 2026 年后才写入 v4 的 CVE
    keep = df[pre & ~late]
    pairs = collect(keep)
    old = json.loads((ROOT / "results" / "label_provenance" / "source_types.json").read_text(encoding="utf-8"))
    lines.append("\nTyping repeated without these CVEs (before 2026, sources with at least 100 dual-scored CVEs):")
    for s, p in sorted(pairs.items(), key=lambda x: -len(x[1])):
        if len(p) >= 100:
            fd = analyse(p)["FD_oos"]
            new_t = "derived" if fd >= THRESHOLD else "independent"
            lines.append(f"- {s}: {len(p):,} pairs, FD_oos {fd:.1%} → {new_t} (original type {old.get(s, {}).get('type', 'none')}, original FD_oos {old.get(s, {}).get('FD_oos_pre2026', float('nan')):.1%})")
    # TF-IDF 基线：去掉这些训练样本后重训
    test = df[df["pub"] >= CUTOFF]
    lines.append("\nTF-IDF baseline retrained without these training samples (same test set):")
    for name, tr in [("original training set", df[pre]), ("without CNA containers updated after the start of 2026", df[pre & ~late])]:
        pred = pred_tfidf_lr(tr, test, with_v31=False)
        for scope, m in [("all", np.ones(len(test), bool)), ("non-derived", (test["label_type"] != "derived").to_numpy())]:
            r = evaluate(test[m].reset_index(drop=True), pred[m].reset_index(drop=True))
            lines.append(f"- {name} (training {len(tr):,}), {scope}: mean macro-F1 {r['mean_macro_f1']:.3f}, band accuracy {r['band_acc']:.3f}, underestimation rate {r['under_rate']:.3f}")


def alt_convention(d31):
    """A conversion convention that is deterministic but differs from rule R: attack complexity moved to AT, UI:R -> A, subsequent-system impacts always N."""
    v = rule_convert(d31)
    v.update({"AC": "L", "AT": "P" if d31["AC"] == "H" else "N", "UI": "N" if d31["UI"] == "N" else "A", "SC": "N", "SI": "N", "SA": "N"})
    return tuple(v[k] for k in M40)


def part_f(df, lines):
    pairs = collect(df[df["pub"] < CUTOFF])
    lines += ["\n## F. Synthetic conversion convention (data before 2026; each source's v4 labels replaced by a deterministic conversion other than rule R, then tested)\n",
              "| CNA | Pairs | Rule-R agreement | FD_oos (rule-R fallback) | FD_oos (seen only) | Fallback rate | Typed as derived |", "|---|---|---|---|---|---|---|"]
    for s, p in sorted(pairs.items(), key=lambda x: -len(x[1])):
        if len(p) < 100:
            continue
        syn = [(t31, d31, alt_convention(d31), None) for t31, d31, _, _ in p]
        agree = np.mean([tuple(rule_convert(d31)[k] for k in M40) == t4 for _, d31, t4, _ in syn])
        r = fd_variants(syn)
        lines.append(f"| {s} | {len(p):,} | {agree:.1%} | {r['fd_R']:.1%} | {r['fd_seen']:.1%} | {r['fallback']:.1%} | {'yes' if r['fd_R'] >= THRESHOLD else 'no'} |")


def main():
    rng = np.random.default_rng(0)
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    test["clean"] = clean_mask(test)
    lines = ["# Robustness checks (second set, generated automatically)\n"]
    for step in [lambda: part_a(df, lines, rng), lambda: part_b(df, lines, rng)]:
        step()
        print("\n".join(lines[-12:]), flush=True)
    tf, ds = part_c(test, lines)
    part_d(df, test, tf, ds, lines)
    print("\n".join(lines[-30:]), flush=True)
    part_e(df, lines)
    part_f(df, lines)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "summary2.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
