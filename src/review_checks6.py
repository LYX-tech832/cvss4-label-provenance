"""Calibration of the functional-dependence test, source characteristics, vendor-cluster resampling and decision-oriented metrics
(CPU, about 20 minutes).

A. Calibration of the functional-dependence test: for each testable source (before 2026, at least 100 dual-scored CVEs), the observed
   FD_oos, the baseline of always guessing the most frequent v4 vector of the training segment, and a permutation null distribution
   that shuffles the v3.1/v4 pairing within the source (200 times); power simulation: labels replaced by a deterministic conversion other
   than rule R (the synthetic convention of review_checks2), then replaced with probability p by a draw from the source's empirical
   distribution, and the share with FD_oos >= 0.90 (50 times); in addition, VulDB's and VulnCheck's v3.1 vectors subsampled to size n, to
   see how the detection rate depends on the sample size.
B. Source characteristics: label diversity (distinct vectors, normalised entropy, share of the most frequent vector), description length,
   CWE diversity; results for each medium or large source (at least 200 CVEs) in the temporal split test set.
C. Resampling by vendor cluster (the vendor is the first vendor in the CNA container's affected list; without one, each CVE forms its own
   cluster), compared with intervals from resampling CVEs; the main comparisons and the ranking reversal under another macro-F1 (averaged
   only over the values present in the labels or predictions, the scikit-learn default).
D. Decision-oriented metrics of risk-sensitive decoding (temporal split test set): High/Critical precision, escalation rate (share
   predicted as High/Critical), severe errors of two or more bands; expected cost at different ratios of underestimation cost to
   overestimation cost.
Output: results/review_checks/summary6.md
"""

import json
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import orjson
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded, fast_scores  # noqa: E402
from baselines_v0 import CUTOFF, M31, M40, SEVERITY_ORDER, load, source_type_map, to_vector, v4_score  # noqa: E402
from cvss_utils import V40_METRICS  # noqa: E402
from label_provenance import collect  # noqa: E402
from review_checks import fd_variants  # noqa: E402
from review_checks2 import alt_convention  # noqa: E402
from risk_decode import ALPHAS, decode  # noqa: E402
from rq1_stats import rule_convert  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
PRED = ROOT / "results" / "baselines_v0" / "predictions"
LLM = ROOT / "results" / "autocvss_baseline" / "deepseek-v4-pro_DTD_s0"
OUT = ROOT / "results" / "review_checks" / "summary6.md"
rng = np.random.default_rng(0)


# ---------------- A ----------------
def fd_oos_only(pairs):
    return fd_variants(pairs)["fd_R"]


def majority_baseline(pairs):
    cut = int(0.7 * len(pairs))
    top = Counter(t4 for _, _, t4, _ in pairs[:cut]).most_common(1)[0][0]
    return np.mean([t4 == top for _, _, t4, _ in pairs[cut:]])


def permuted(pairs):
    v4 = [p[2] for p in pairs]
    perm = rng.permutation(len(v4))
    return [(p[0], p[1], v4[j], None) for p, j in zip(pairs, perm)]


def noisy_synthetic(pairs, p):
    pool = [x[2] for x in pairs]
    out = []
    for t31, d31, _, _ in pairs:
        t4 = alt_convention(d31)
        if rng.random() < p:
            t4 = pool[rng.integers(len(pool))]
        out.append((t31, d31, t4, None))
    return out


def part_a(df, lines):
    pairs = {s: p for s, p in collect(df[df["pub"] < CUTOFF]).items() if len(p) >= 100}
    lines += ["## A. Calibration of the functional-dependence test (sources with at least 100 dual-scored CVEs before 2026)\n",
              "| Source | Pairs | FD_oos (observed) | Most-frequent-vector baseline | Permutation null mean / 95th percentile | Detection rate with synthetic conversion + noise p=0 / 0.05 / 0.10 / 0.20 (50 times) |", "|---|---|---|---|---|---|"]
    for s, p in sorted(pairs.items(), key=lambda x: -len(x[1])):
        null = [fd_oos_only(permuted(p)) for _ in range(200)]
        det = []
        for noise in (0.0, 0.05, 0.10, 0.20):
            det.append(np.mean([fd_oos_only(noisy_synthetic(p, noise)) >= 0.90 for _ in range(50)]))
        lines.append(f"| {s} | {len(p):,} | {fd_oos_only(p):.3f} | {majority_baseline(p):.3f} | {np.mean(null):.3f} / {np.percentile(null, 95):.3f} | "
                     + " / ".join(f"{x:.2f}" for x in det) + " |")
    lines += ["\nDetection rate by sample size (synthetic conversion, no noise; n of the source's dual-scored CVEs before 2026; 50 random subsamples, each kept in time order)\n",
              "| v3.1 vectors from | n=100 | n=200 | n=500 | n=1,000 | n=2,000 |", "|---|---|---|---|---|---|"]
    for s in ["VulDB", "VulnCheck", "siemens", "intel"]:
        if s not in pairs:
            continue
        p = pairs[s]
        cells = []
        for n in (100, 200, 500, 1000, 2000):
            if n > len(p):
                cells.append("—")
                continue
            hits = []
            for _ in range(50):
                idx = np.sort(rng.choice(len(p), size=n, replace=False))
                hits.append(fd_oos_only(noisy_synthetic([p[i] for i in idx], 0.0)) >= 0.90)
            cells.append(f"{np.mean(hits):.2f}")
        lines.append(f"| {s} ({len(p):,} in total) | " + " | ".join(cells) + " |")


# ---------------- B ----------------
def entropy(counts):
    c = np.array(list(counts.values()), dtype=float)
    q = c / c.sum()
    h = -(q * np.log2(q)).sum()
    return h / np.log2(len(c)) if len(c) > 1 else 0.0


def part_b(df, test, preds, lines):
    df = df.assign(vec=df[["y_" + k for k in M40]].astype(str).agg("/".join, axis=1),
                   dlen=df["description"].str.split().str.len(),
                   cwe=[(list(a) + list(b))[0] if len(a) + len(b) else None for a, b in zip(df["cwe_cna"], df["cwe_adp"])])
    groups = [("VulDB (derived)", df["source"] == "VulDB"), ("VulnCheck", df["source"] == "VulnCheck"), ("GitHub_M (v4-only)", df["source"] == "GitHub_M"),
              ("other independent sources", (df["label_type"] == "independent") & (df["source"] != "VulnCheck")),
              ("other v4-only sources", (df["label_type"] == "v4_only") & (df["source"] != "GitHub_M")), ("other", df["label_type"] == "other")]
    lines += ["\n## B. Source characteristics (all v4.0 labels)\n",
              "| Source | n | Distinct v4 vectors | Normalised entropy of the vector distribution | Share of the most frequent vector | Median words per description | Share with a CWE | Distinct CWEs | Share of the top 3 CWEs |", "|---|---|---|---|---|---|---|---|---|"]
    for name, m in groups:
        g = df[m]
        vc = Counter(g["vec"])
        cw = g["cwe"].dropna()
        top3 = sum(c for _, c in Counter(cw).most_common(3)) / len(cw) if len(cw) else float("nan")
        lines.append(f"| {name} | {len(g):,} | {len(vc):,} | {entropy(vc):.2f} | {vc.most_common(1)[0][1] / len(g):.1%} | {int(g['dlen'].median())} | "
                     f"{len(cw) / len(g):.1%} | {cw.nunique():,} | {top3:.1%} |")
    # 各来源的测试结果
    t = Encoded(test, "y_")
    maj = Encoded(pd.read_parquet(PRED / "T2_temporal_majority.parquet").set_index("cve_id").loc[test["cve_id"]].reset_index())
    lines += ["\nResults of each source (at least 200 CVEs) in the temporal split test set: mean macro-F1 / band accuracy\n", "| Source | Type | n | Majority | TF-IDF | DeBERTa | DeBERTa + auxiliary |", "|---|---|---|---|---|---|---|"]
    for s, n in test["source"].value_counts().items():
        if n < 200:
            continue
        idx = np.flatnonzero(test["source"].to_numpy() == s)
        cells = [fast_scores(t, maj, idx)]
        for key in ["tfidf", "none", "aux"]:
            rs = [fast_scores(t, e, idx) for e in preds[key]]
            cells.append({k: np.mean([r[k] for r in rs]) for k in ["mean_macro_f1", "band_acc"]})
        lines.append(f"| {s} | {test.loc[idx[0], 'label_type']} | {n:,} | " + " | ".join(f"{c['mean_macro_f1']:.3f} / {c['band_acc']:.3f}" for c in cells) + " |")


# ---------------- C ----------------
def vendors(ids):
    want = set(ids)
    out = {}
    with zipfile.ZipFile(ROOT / "data" / "raw" / "cves.zip") as z:
        for n in z.namelist():
            base = n.rsplit("/", 1)[-1][:-5] if n.endswith(".json") else None
            if base in want:
                cna = ((orjson.loads(z.read(n)).get("containers") or {}).get("cna") or {})
                aff = cna.get("affected") or []
                v = (aff[0].get("vendor") or "").strip().lower() if aff else ""
                out[base] = v if v and v not in ("n/a", "unknown") else None
    return out


def present_f1(t, p, idx):
    """Macro-F1 averaged only over the values present in the labels or predictions (scikit-learn default), then averaged over the 11 metrics."""
    f1s = []
    for k in M40:
        n_cls = len(V40_METRICS[k])
        cm = np.bincount(t.codes[k][idx] * n_cls + p.codes[k][idx], minlength=n_cls * n_cls).reshape(n_cls, n_cls)
        tp = np.diag(cm)
        support = cm.sum(0) + cm.sum(1)
        denom = 2 * tp + (cm.sum(0) - tp) + (cm.sum(1) - tp)
        f = np.where(denom > 0, 2 * tp / np.maximum(denom, 1), 0.0)
        f1s.append(f[support > 0].mean())
    return float(np.mean(f1s))


def cluster_boot(cl, idx, stat, B=1000):
    """Cluster resampling: draw clusters, then take all CVEs of each drawn cluster."""
    groups = defaultdict(list)
    for i in idx:
        groups[cl[i]].append(i)
    keys = list(groups)
    out = []
    for _ in range(B):
        pick = rng.integers(len(keys), size=len(keys))
        out.append(stat(np.concatenate([groups[keys[j]] for j in pick])))
    return np.percentile(out, [2.5, 97.5])


def part_c(df, test, preds, lines):
    v = vendors(test["cve_id"])
    cl = np.array([v.get(c) or c for c in test["cve_id"]])
    t = Encoded(test, "y_")
    nd = np.flatnonzero(test["label_type"].to_numpy() != "derived")
    allx = np.arange(len(test))
    lines += ["\n## C. Resampling by vendor cluster (temporal split test set)\n",
              f"Test CVEs with vendor information {sum(1 for c in test['cve_id'] if v.get(c)):,} / {len(test):,}; clusters {len(set(cl)):,}; largest cluster {Counter(cl).most_common(1)[0][1]:,} CVEs ({Counter(cl).most_common(1)[0][0]}).\n",
              "| Comparison | Scope | Difference | 95% interval, resampling CVEs | 95% interval, resampling vendor clusters |", "|---|---|---|---|---|"]

    def diff(a, b, key="mean_macro_f1"):
        def f(ix):
            return np.mean([fast_scores(t, e, ix)[key] for e in preds[a]]) - np.mean([fast_scores(t, e, ix)[key] for e in preds[b]])
        return f
    for name, idx in [("all", allx), ("non-derived", nd)]:
        for a, b, key in [("aux", "none", "mean_macro_f1"), ("aux", "none", "band_acc"), ("aux", "tfidf", "mean_macro_f1")]:
            f = diff(a, b, key)
            pt = f(idx)
            cve = np.percentile([f(rng.choice(idx, size=len(idx), replace=True)) for _ in range(1000)], [2.5, 97.5])
            clu = cluster_boot(cl, idx, f)
            lines.append(f"| {a} − {b} ({key}) | {name} | {pt:+.3f} | [{cve[0]:+.3f}, {cve[1]:+.3f}] | [{clu[0]:+.3f}, {clu[1]:+.3f}] |")

    # 大模型样本：排名翻转（类型内分簇重抽样）+ 另一种宏 F1
    llm = pd.read_parquet(LLM / "predictions.parquet")
    ids = llm["cve_id"]
    s = df.set_index("cve_id").loc[ids].reset_index()
    ts = Encoded(s, "y_")
    e_llm = Encoded(llm.set_index("cve_id").loc[ids].reset_index())
    e_tf = Encoded(pd.read_parquet(PRED / "T2_temporal_tfidf_lr.parquet").set_index("cve_id").loc[ids].reset_index())
    aux_s = [Encoded(pd.read_parquet(d / "pred_latent.parquet").set_index("cve_id").loc[ids].reset_index())
             for d in sorted(ENC.glob("T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s[0-9]"))]
    cls = np.array([v.get(c) or c for c in s["cve_id"]])
    lt = s["label_type"].to_numpy()
    lines += ["\nLLM sample (2,000 CVEs): mean macro-F1 difference DeepSeek − TF-IDF; cluster resampling by vendor within each label type\n",
              "| Scope | Difference | 95% interval, CVEs (within types) | 95% interval, vendor clusters (within types) |", "|---|---|---|---|"]
    for name, types in [("whole sample", ["derived", "independent", "v4_only", "other"]), ("non-derived", ["independent", "v4_only", "other"])]:
        strata = [np.flatnonzero(lt == ty) for ty in types]
        idx = np.concatenate(strata)

        def f(ix):
            return fast_scores(ts, e_llm, ix)["mean_macro_f1"] - fast_scores(ts, e_tf, ix)["mean_macro_f1"]
        cve = np.percentile([f(np.concatenate([rng.choice(x, size=len(x), replace=True) for x in strata])) for _ in range(1000)], [2.5, 97.5])
        clu_draws = []
        grp = [defaultdict(list) for _ in strata]
        for gi, x in enumerate(strata):
            for i in x:
                grp[gi][cls[i]].append(i)
        for _ in range(1000):
            parts = []
            for g in grp:
                keys = list(g)
                pick = rng.integers(len(keys), size=len(keys))
                parts.append(np.concatenate([g[keys[j]] for j in pick]))
            clu_draws.append(f(np.concatenate(parts)))
        clu = np.percentile(clu_draws, [2.5, 97.5])
        lines.append(f"| {name} | {f(idx):+.3f} | [{cve[0]:+.3f}, {cve[1]:+.3f}] | [{clu[0]:+.3f}, {clu[1]:+.3f}] |")

    lines += ["\nAnother macro-F1 (averaged only over the values present in the labels or predictions): the methods on the LLM sample\n",
              "| Method | Whole sample | Non-derived | derived | independent | v4-only | other |", "|---|---|---|---|---|---|---|"]
    scopes = [np.arange(len(s)), np.flatnonzero(lt != "derived")] + [np.flatnonzero(lt == ty) for ty in ["derived", "independent", "v4_only", "other"]]
    for name, es in [("DeepSeek-V4-Pro", [e_llm]), ("TF-IDF + LR", [e_tf]), ("DeBERTa + auxiliary (5 seeds)", aux_s)]:
        lines.append(f"| {name} | " + " | ".join(f"{np.mean([present_f1(ts, e, ix) for e in es]):.3f}" for ix in scopes) + " |")
    d_pool = present_f1(ts, e_llm, scopes[0]) - present_f1(ts, e_tf, scopes[0])
    d_nd = present_f1(ts, e_llm, scopes[1]) - present_f1(ts, e_tf, scopes[1])
    boots = []
    strata = [np.flatnonzero(lt == ty) for ty in ["derived", "independent", "v4_only", "other"]]
    for _ in range(1000):
        b = [rng.choice(x, size=len(x), replace=True) for x in strata]
        pool, ndx = np.concatenate(b), np.concatenate(b[1:])
        boots.append((present_f1(ts, e_llm, pool) - present_f1(ts, e_tf, pool), present_f1(ts, e_llm, ndx) - present_f1(ts, e_tf, ndx)))
    boots = np.array(boots)
    lines.append(f"\nWith this macro-F1, DeepSeek − TF-IDF: whole sample {d_pool:+.3f} [{np.percentile(boots[:, 0], 2.5):+.3f}, {np.percentile(boots[:, 0], 97.5):+.3f}]; "
                 f"non-derived {d_nd:+.3f} [{np.percentile(boots[:, 1], 2.5):+.3f}, {np.percentile(boots[:, 1], 97.5):+.3f}].")
    # 主结果的另一种宏 F1
    lines += ["\nTemporal split test set, the other macro-F1: all / non-derived\n", "| Method | All | Non-derived |", "|---|---|---|"]
    for name, key in [("TF-IDF", "tfidf"), ("DeBERTa", "none"), ("DeBERTa + auxiliary", "aux")]:
        lines.append(f"| {name} | {np.mean([present_f1(t, e, allx) for e in preds[key]]):.3f} | {np.mean([present_f1(t, e, nd) for e in preds[key]]):.3f} |")


# ---------------- D ----------------
def bands_from(frame):
    vec = frame[M40].apply(to_vector, axis=1)
    return np.array([SEVERITY_ORDER.get(v4_score(x)[1], -1) for x in vec])


def decision_metrics(tb, pb):
    hc_t, hc_p = tb >= 3, pb >= 3
    return {"band": (tb == pb).mean(), "under": (pb < tb).mean(), "over": (pb > tb).mean(),
            "hc_prec": (hc_t & hc_p).sum() / max(hc_p.sum(), 1), "hc_rec": (hc_t & hc_p).sum() / max(hc_t.sum(), 1),
            "escalate": hc_p.mean(), "severe": (np.abs(pb - tb) >= 2).mean()}


def part_d(df, test, lines):
    tb = bands_from(test.rename(columns={"y_" + k: k for k in M40}))
    runs = sorted(ENC.glob("T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s[0-9]"))
    by_alpha = defaultdict(list)
    for d in runs:
        z = np.load(d / "probs.npz")
        pos = pd.Series(np.arange(len(test)), index=test["cve_id"]).loc[z["test_cve_id"]].to_numpy()
        tbx = tb[pos]
        chosen = json.loads((d / "risk_decode.json").read_text(encoding="utf-8"))["chosen_alpha"]
        for a in ALPHAS:
            pb = bands_from(decode({k: z[f"test_{k}"] for k in M40}, a))
            m = decision_metrics(tbx, pb)
            by_alpha[a].append(m)
            if abs(a - chosen) < 1e-9:
                by_alpha["chosen"].append(m)
    keys = ["band", "under", "over", "hc_prec", "hc_rec", "escalate", "severe"]
    lines += ["\n## D. Decision-oriented metrics of risk-sensitive decoding (DeBERTa + auxiliary, temporal split test set, mean over 5 seeds)\n",
              "| Decoding | Band accuracy | Underestimation | Overestimation | H+C precision | H+C recall | Escalation rate (predicted H/C) | Errors of two or more bands |", "|---|---|---|---|---|---|---|---|"]
    for a in [1.0, "chosen"] + [x for x in ALPHAS if x < 1.0]:
        ms = by_alpha[a]
        lines.append(f"| {'argmax' if a == 1.0 else ('α selected on validation data' if a == 'chosen' else f'α = {a:.1f}')} | " + " | ".join(f"{np.mean([m[k] for m in ms]):.3f}" for k in keys) + " |")
    lines.append(f"\nShare of High/Critical among the true labels: {(tb >= 3).mean():.3f}")
    # 期望代价：每个 CVE 低估记 r、高估记 1
    lines += ["\nExpected cost (r per underestimate, 1 per overestimate; test values at each α; DeBERTa + auxiliary averaged over 5 seeds; TF-IDF and the pipeline from the scan in risk_baselines)\n",
              "| Method | α with the lowest cost at r = 1 | r = 2 | r = 5 | r = 10 |", "|---|---|---|---|---|"]
    curves = {"DeBERTa + auxiliary": {a: (np.mean([m["under"] for m in by_alpha[a]]), np.mean([m["over"] for m in by_alpha[a]])) for a in ALPHAS}}
    rb = json.loads((ROOT / "results" / "review_checks" / "risk_baselines_temporal.json").read_text(encoding="utf-8"))
    for name, key in [("TF-IDF", "tfidf"), ("pipeline (rule R)", "pipeline_R")]:
        curves[name] = {r["alpha"]: (r["test_under_rate"], 1 - r["test_band_acc"] - r["test_under_rate"]) for r in rb[key]["scan"]}
    for name, c in curves.items():
        cells = []
        for r in (1, 2, 5, 10):
            costs = {a: r * u + o for a, (u, o) in c.items()}
            best = min(costs, key=costs.get)
            cells.append(f"α = {best:.1f} (cost {costs[best]:.3f}; argmax {costs[1.0]:.3f})")
        lines.append(f"| {name} | " + " | ".join(cells) + " |")


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    ids = test["cve_id"]
    preds = {"tfidf": [Encoded(pd.read_parquet(PRED / "T2_temporal_tfidf_lr.parquet").set_index("cve_id").loc[ids].reset_index())],
             "none": [Encoded(pd.read_parquet(d / "pred_latent.parquet").set_index("cve_id").loc[ids].reset_index())
                      for d in sorted(ENC.glob("T2_temporal_deberta-v3-base_none_e5_cwinv_sqrt_s[0-9]"))],
             "aux": [Encoded(pd.read_parquet(d / "pred_latent.parquet").set_index("cve_id").loc[ids].reset_index())
                     for d in sorted(ENC.glob("T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s[0-9]"))]}
    lines = ["# Calibration of the functional-dependence test, source characteristics, vendor-cluster resampling and decision-oriented metrics (generated automatically)\n"]
    for step in (lambda: part_a(df, lines), lambda: part_b(df, test, preds, lines), lambda: part_c(df, test, preds, lines), lambda: part_d(df, test, lines)):
        step()
        OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print("\n".join(lines[-6:]), flush=True)
    print("\n".join(lines))


if __name__ == "__main__":
    main()
