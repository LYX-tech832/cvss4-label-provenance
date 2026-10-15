"""Robustness checks, first set (CPU, a few minutes).

(a) Robustness of FD_oos: share of v3.1 vectors in the test segment not seen in the training segment (fallback rate); FD_oos and the
    typing at 0.90 under three fallbacks (rule R / the most frequent v4 vector of the training segment / no fallback, seen vectors only);
    Wilson 95% intervals. On all data and on data before 2026 (the typing window).
(b) The R-inconsistent subset: dual-scored CVEs whose v4.0 vector differs from rule R(v3.1). Do the evaluation inflation (all /
    non-derived / this subset) and the ranking reversal hold on it?
(c) AutoCVSS post-processing: the difference between DeepSeek and TF-IDF when DONT_KNOW is replaced by the most frequent training value
    (by label type, paired bootstrap within types).
(d) Monotonicity of CVSS v4.0 scoring: can the CVSS-B score or band decrease when any metric is made one step more severe (exhaustive
    over all 104,976 base vectors)?
(e) Shares of CNA and ADP labels in the v3.1 auxiliary pool.
(f) Within each split, the number of the 5 seeds on which the auxiliary variant wins.
(g) Upper bound of temporal leakage: share of v4 training and typing samples published before 2026 whose record was updated after the
    start of 2026 (record-level update time, hence an upper bound).
Output: results/review_checks/summary.md
"""

import itertools
import json
import sys
from collections import Counter, defaultdict
from math import sqrt
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded, fast_scores  # noqa: E402
from baselines_v0 import CUTOFF, M31, M40, evaluate, load, source_type_map, v4_score, SEVERITY_ORDER  # noqa: E402
from label_provenance import collect  # noqa: E402
from pilot_transfer import v31_pool  # noqa: E402
from rq1_stats import rule_convert  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "review_checks"
ENC = ROOT / "results" / "encoder"
LLM = ROOT / "results" / "autocvss_baseline" / "deepseek-v4-pro_DTD_s0"
PRED = ROOT / "results" / "baselines_v0" / "predictions"
ORDER = {"AV": "NALP", "AC": "LH", "AT": "NP", "PR": "NLH", "UI": "NPA", "VC": "HLN", "VI": "HLN", "VA": "HLN",
         "SC": "HLN", "SI": "HLN", "SA": "HLN"}  # 从最严重到最不严重（与风险敏感解码一致）


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (c - h, c + h)


def fd_variants(pairs):
    n = len(pairs)
    cut = int(0.7 * n)
    learn = defaultdict(Counter)
    for t31, _, t4, _ in pairs[:cut]:
        learn[t31][t4] += 1
    mapping = {k: c.most_common(1)[0][0] for k, c in learn.items()}
    majority = Counter(t4 for _, _, t4, _ in pairs[:cut]).most_common(1)[0][0]
    test = pairs[cut:]
    seen = [t31 in mapping for t31, _, _, _ in test]
    hit_r = [mapping.get(t31, tuple(rule_convert(d31)[k] for k in M40)) == t4 for t31, d31, t4, _ in test]
    hit_m = [mapping.get(t31, majority) == t4 for t31, _, t4, _ in test]
    hit_s = [mapping[t31] == t4 for t31, _, t4, _ in test if t31 in mapping]
    return {"n_test": len(test), "fallback": 1 - np.mean(seen), "fd_R": np.mean(hit_r), "ci": wilson(sum(hit_r), len(test)),
            "fd_maj": np.mean(hit_m), "fd_seen": np.mean(hit_s) if hit_s else float("nan")}


def part1(df, lines):
    lines += ["\n## (a) Fallbacks of FD_oos and confidence intervals\n",
              "Fallback = share of v3.1 vectors in the test segment (the last 30%) not seen in the training segment. Three fallbacks: rule R (used in the paper) / the most frequent v4 vector of the training segment / none (seen vectors only). ",
              "Intervals are Wilson 95% intervals with the rule-R fallback.\n"]
    for name, sub in [("all data", df), ("before 2026 (typing window)", df[df["pub"] < CUTOFF])]:
        pairs = collect(sub)
        lines += [f"\n### {name}\n", "| CNA | Pairs | Test segment n | Fallback rate | FD_oos (rule-R fallback) | 95% interval | FD_oos (most-frequent fallback) | FD_oos (seen only) | Typing at 0.90 changes with the fallback |",
                  "|---|---|---|---|---|---|---|---|---|"]
        for s, p in sorted(pairs.items(), key=lambda x: -len(x[1])):
            if len(p) < 100:
                continue
            r = fd_variants(p)
            types = {v >= 0.90 for v in [r["fd_R"], r["fd_maj"]] + ([r["fd_seen"]] if not np.isnan(r["fd_seen"]) else [])}
            lines.append(f"| {s} | {len(p):,} | {r['n_test']} | {r['fallback']:.1%} | {r['fd_R']:.1%} | [{r['ci'][0]:.1%}, {r['ci'][1]:.1%}] | "
                         f"{r['fd_maj']:.1%} | {r['fd_seen']:.1%} | {'**yes**' if len(types) > 1 else 'no'} |")


def clean_mask(df):
    """Dual-scored and the v4.0 vector differs from rule R(same-source v3.1)."""
    out = np.zeros(len(df), bool)
    for i, (_, r) in enumerate(df.iterrows()):
        if not r["has_v31"]:
            continue
        conv = rule_convert({k: r["x31_" + k] for k in M31})
        out[i] = any(conv[k] != r["y_" + k] for k in M40)
    return out


def scores(t, p):
    r = evaluate(t.reset_index(drop=True), p.reset_index(drop=True))
    return r["mean_macro_f1"], r["band_acc"]


def aligned(path, ids):
    return pd.read_parquet(path).set_index("cve_id").loc[ids].reset_index()


def part2_3(df, lines):
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    test["clean"] = clean_mask(test)
    tfidf = aligned(PRED / "T2_temporal_tfidf_lr.parquet", test["cve_id"])
    aux = [aligned(f, test["cve_id"]) for f in sorted(ENC.glob("T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s[0-9]/pred_latent.parquet"))]
    lines += ["\n## (b) The R-inconsistent subset: dual-scored and v4.0 ≠ rule R(v3.1)\n",
              f"Temporal split test set: all {len(test):,}; non-derived {int((test['label_type'] != 'derived').sum()):,}; R-inconsistent subset {int(test['clean'].sum()):,}"
              f" (of which derived labels {int((test['clean'] & (test['label_type'] == 'derived')).sum())}).\n",
              "| Method | Scope | n | Mean macro-F1 | Band accuracy |", "|---|---|---|---|---|"]
    for scope, m in [("all", np.ones(len(test), bool)), ("non-derived", (test["label_type"] != "derived").to_numpy()), ("R-inconsistent subset", test["clean"].to_numpy())]:
        f, b = scores(test[m], tfidf[m])
        lines.append(f"| TF-IDF + LR | {scope} | {int(m.sum()):,} | {f:.3f} | {b:.3f} |")
        rs = [scores(test[m], p[m]) for p in aux]
        lines.append(f"| DeBERTa + v3.1 auxiliary (mean of 5 seeds) | {scope} | {int(m.sum()):,} | {np.mean([r[0] for r in rs]):.3f} | {np.mean([r[1] for r in rs]):.3f} |")

    # LLM 样本
    llm = pd.read_parquet(LLM / "predictions.parquet")
    ids = llm["cve_id"]
    s = df.set_index("cve_id").loc[ids].reset_index()
    s["clean"] = clean_mask(s)
    raw = [json.loads(line) for line in (LLM / "raw.jsonl").read_text(encoding="utf-8").splitlines()]
    unknown = {(r["cve_id"], r["metric"]) for r in raw if r["label"] in (None, "DONT_KNOW")}
    train = df[df["pub"] < CUTOFF]
    majority = {k: train["y_" + k].mode()[0] for k in M40}
    alt = llm.set_index("cve_id").loc[ids].reset_index()
    pos = {c: i for i, c in enumerate(alt["cve_id"])}
    for cve, k in unknown:
        if cve in pos:
            alt.iloc[pos[cve], alt.columns.get_loc(k)] = majority[k]
    methods = {"DeepSeek (as in AutoCVSS)": llm.set_index("cve_id").loc[ids].reset_index(), "DeepSeek (DONT_KNOW → most frequent)": alt,
               "TF-IDF": aligned(PRED / "T2_temporal_tfidf_lr.parquet", ids)}
    t = Encoded(s, "y_")
    enc = {n: Encoded(p) for n, p in methods.items()}
    lt = s["label_type"].to_numpy()
    rng = np.random.default_rng(0)
    scopes = {"whole sample": ["derived", "independent", "v4_only", "other"], "without derived": ["independent", "v4_only", "other"],
              "independent": ["independent"], "v4_only": ["v4_only"], "other": ["other"], "derived": ["derived"]}
    lines += ["\n## (c) AutoCVSS post-processing: DONT_KNOW → most frequent training value (the same 2,000 CVEs; paired bootstrap within types, 1,000 resamples)\n",
              f"(CVE, metric) pairs with DONT_KNOW or a failed request: {len(unknown):,} ({len(unknown) / (len(ids) * 11):.1%}).\n",
              "| Scope | n | DeepSeek as in AutoCVSS macro-F1 / band | DeepSeek most frequent macro-F1 / band | TF-IDF macro-F1 / band | (most frequent − TF-IDF) macro-F1 difference [95%] | Band accuracy difference [95%] |",
              "|---|---|---|---|---|---|---|"]
    for name, types in scopes.items():
        strata = [np.flatnonzero(lt == ty) for ty in types]
        idx = np.concatenate(strata)
        pt = {n: fast_scores(t, e, idx) for n, e in enc.items()}
        diffs = []
        for _ in range(1000):
            b = np.concatenate([rng.choice(x, size=len(x), replace=True) for x in strata])
            a, c = fast_scores(t, enc["DeepSeek (DONT_KNOW → most frequent)"], b), fast_scores(t, enc["TF-IDF"], b)
            diffs.append((a["mean_macro_f1"] - c["mean_macro_f1"], a["band_acc"] - c["band_acc"]))
        d = np.array(diffs)
        cell = lambda n: f"{pt[n]['mean_macro_f1']:.3f} / {pt[n]['band_acc']:.3f}"  # noqa: E731
        df1 = pt["DeepSeek (DONT_KNOW → most frequent)"]["mean_macro_f1"] - pt["TF-IDF"]["mean_macro_f1"]
        db = pt["DeepSeek (DONT_KNOW → most frequent)"]["band_acc"] - pt["TF-IDF"]["band_acc"]
        lines.append(f"| {name} | {len(idx):,} | {cell('DeepSeek (as in AutoCVSS)')} | {cell('DeepSeek (DONT_KNOW → most frequent)')} | {cell('TF-IDF')} | "
                     f"{df1:+.3f} [{np.percentile(d[:, 0], 2.5):+.3f}, {np.percentile(d[:, 0], 97.5):+.3f}] | "
                     f"{db:+.3f} [{np.percentile(d[:, 1], 2.5):+.3f}, {np.percentile(d[:, 1], 97.5):+.3f}] |")
    # 干净子集上的 LLM 对比（原做法）
    m = s["clean"].to_numpy()
    idx = np.flatnonzero(m)
    diffs = []
    for _ in range(1000):
        b = rng.choice(idx, size=len(idx), replace=True)
        diffs.append(fast_scores(t, enc["DeepSeek (as in AutoCVSS)"], b)["mean_macro_f1"] - fast_scores(t, enc["TF-IDF"], b)["mean_macro_f1"])
    a, c = fast_scores(t, enc["DeepSeek (as in AutoCVSS)"], idx), fast_scores(t, enc["TF-IDF"], idx)
    lines.append(f"\nR-inconsistent subset of the sample (n = {len(idx)}): DeepSeek (as in AutoCVSS) macro-F1 {a['mean_macro_f1']:.3f} / band {a['band_acc']:.3f}; "
                 f"TF-IDF {c['mean_macro_f1']:.3f} / {c['band_acc']:.3f}; macro-F1 difference {a['mean_macro_f1'] - c['mean_macro_f1']:+.3f} "
                 f"[{np.percentile(diffs, 2.5):+.3f}, {np.percentile(diffs, 97.5):+.3f}].")


def part4(lines):
    vals = [ORDER[k] for k in M40]
    viol_score, viol_band, total = Counter(), Counter(), 0
    for combo in itertools.product(*vals):
        vec = dict(zip(M40, combo))
        s0, b0 = v4_score("CVSS:4.0/" + "/".join(f"{k}:{vec[k]}" for k in M40))
        for k in M40:
            i = ORDER[k].index(vec[k])
            if i == 0:
                continue
            up = dict(vec, **{k: ORDER[k][i - 1]})
            s1, b1 = v4_score("CVSS:4.0/" + "/".join(f"{m}:{up[m]}" for m in M40))
            total += 1
            if s1 < s0 - 1e-9:
                viol_score[k] += 1
            if SEVERITY_ORDER.get(b1, -1) < SEVERITY_ORDER.get(b0, -1):
                viol_band[k] += 1
    lines += ["\n## (d) Monotonicity of CVSS v4.0 scoring (all base vectors, each metric made one step more severe)\n",
              f"(vector, metric) combinations checked: {total:,}; with a lower score: {sum(viol_score.values()):,} (by metric: {dict(viol_score) or 'none'}); "
              f"with a lower band: {sum(viol_band.values()):,} (by metric: {dict(viol_band) or 'none'})."]


def part5(lines):
    pool = v31_pool(before_cutoff=True)
    cna = pool["cna_v31"].map(len) > 0
    lines += ["\n## (e) Sources of the labels in the v3.1 auxiliary pool (before 2026)\n",
              f"{len(pool):,} in total: from CNA containers {int(cna.sum()):,} ({cna.mean():.1%}), from ADP containers {int((~cna).sum()):,} ({(~cna).mean():.1%})."]


def part6(lines):
    lines += ["\n## (f) Seeds on which the auxiliary variant wins, within each split (mean macro-F1, all test labels)\n", "| Split | Winning seeds / 5 | Difference per seed |", "|---|---|---|"]
    for split in ["temporal", "loso-VulnCheck", "loso-GitHub_M", "loso-VulDB"]:
        d = []
        for s in range(5):
            a = ENC / f"T2_{split}_deberta-v3-base_none_aux_e5_cwinv_sqrt_s{s}" / "results.json"
            b = ENC / f"T2_{split}_deberta-v3-base_none_e5_cwinv_sqrt_s{s}" / "results.json"
            if a.exists() and b.exists():
                d.append(json.loads(a.read_text(encoding="utf-8"))["latent"]["mean_macro_f1"] - json.loads(b.read_text(encoding="utf-8"))["latent"]["mean_macro_f1"])
        lines.append(f"| {split} | {sum(x > 0 for x in d)} / {len(d)} | " + ", ".join(f"{x:+.3f}" for x in d) + " |")


def part7(df, lines):
    upd = pd.to_datetime(df["date_updated"], utc=True, errors="coerce")
    pre = df["pub"] < CUTOFF
    late = upd >= CUTOFF
    dual = df["has_v31"]
    lines += ["\n## (g) Upper bound of temporal leakage (record-level update time; a record update is not necessarily a change of the v4.0 vector, hence an upper bound)\n",
              f"- v4 samples published before 2026 (training + validation parts of the temporal split): {int(pre.sum()):,}, of which {int((pre & late).sum()):,} with a record updated after the start of 2026 ({(pre & late).sum() / pre.sum():.1%}); ",
              f"- of these, dual-scored (used for the typing): {int((pre & dual).sum()):,}, updated after the start of 2026 {int((pre & dual & late).sum()):,} ({(pre & dual & late).sum() / (pre & dual).sum():.1%}); ",
              "- by source (share updated after the start of 2026, sources with at least 500 v4 samples in the training part): " + "; ".join(
                  f"{s} {g:.1%}" for s, g in df[pre].assign(late=late[pre]).groupby("source")["late"].agg(["mean", "size"]).query("size >= 500")["mean"].sort_values(ascending=False).items())]


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    lines = ["# Robustness checks (first set, generated automatically)\n"]
    part1(df, lines)
    part2_3(df, lines)
    part4(lines)
    part5(lines)
    part6(lines)
    part7(df, lines)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
