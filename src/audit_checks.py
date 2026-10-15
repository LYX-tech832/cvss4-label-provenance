"""Further controls: simple alternative explanations of the main findings (CPU, about 20 minutes).

A. Are VulDB's labels easier to predict only because it has the most training labels? Each source trains TF-IDF + LR on only 1,000 of
   its own v4.0 labels from before 2026 (5 random draws) and is tested on its own labels of 2026; for VulDB, the same 1,000 CVEs are
   also used with their v3.1 labels.
B. Is the change of ranking with the label source limited to one case (LLM vs TF-IDF, macro-F1)? On the complete temporal split test
   set, paired differences between the models that predict v4.0 directly and the pipelines that use no v4.0 labels (predict v3.1, then
   convert with rule R), on all and on non-derived labels (test CVEs resampled 1,000 times). The per-CVE predictions of the pipelines
   are recomputed here and saved to results/pipeline_baseline/predictions/.
C. Is the change of conversion practice over time (VulnCheck's rising agreement with the rule) a change of composition caused by
   back-filling old vulnerabilities? VulnCheck's quarterly agreement with rule R, separately for CVE identifiers at least two years
   older than the publication year.
D. All pairwise comparisons of the methods on the 2,000-CVE LLM sample: do the pooled and the non-derived differences have opposite
   signs (resampling within label types, 1,000 times)?
Output: results/review_checks/summary12.md
"""

import sys
from itertools import combinations
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import cohen_kappa_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded, fast_scores  # noqa: E402
from baselines_v0 import CUTOFF, M31, M40, load, source_type_map  # noqa: E402
from pilot_transfer import v31_pool  # noqa: E402
from pipeline_baseline import convert, stage1  # noqa: E402
from review_checks9 import band31, fit_predict  # noqa: E402
from rq1_stats import rule_convert  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
PRED = ROOT / "results" / "baselines_v0" / "predictions"
PIPE = ROOT / "results" / "pipeline_baseline" / "predictions"
LLM = ROOT / "results" / "autocvss_baseline"
OUT = ROOT / "results" / "review_checks" / "summary12.md"
rng = np.random.default_rng(0)
KEYS = ("mean_macro_f1", "band_acc", "under_rate")


def part_a(df, lines):
    lines += ["## A. Each source trained on only 1,000 of its own labels (TF-IDF + LR; mean of 5 random draws), tested on its own labels of 2026\n",
              "| Source | v4.0 labels before 2026 | Test labels | Labels | Base rate | Band accuracy | κ | Mean macro-F1 |", "|---|---|---|---|---|---|---|---|"]
    for src in ["VulDB", "VulnCheck", "GitHub_M"]:
        d = df[df["source"] == src]
        tr_all, te = d[d["pub"] < CUTOFF], d[d["pub"] >= CUTOFF].reset_index(drop=True)
        t = Encoded(te, "y_")
        idx = np.arange(len(te))
        versions = [("v4.0", None)] + ([("v3.1", "x31_")] if src == "VulDB" else [])
        for ver, pre in versions:
            accs, kaps, f1s = [], [], []
            for draw in range(5):
                tr = tr_all.sample(1000, random_state=draw)
                if pre is None:
                    p = fit_predict(tr["text"], te["text"], {k: tr["y_" + k].values for k in M40})
                    e = Encoded(p.assign(cve_id=te["cve_id"]))
                    tb, pb = t.band, e.band
                    f1s.append(fast_scores(t, e, idx)["mean_macro_f1"])
                else:
                    from review_checks9 import macro_f1
                    from cvss_utils import V31_METRICS
                    p = fit_predict(tr["text"], te["text"], {k: tr[pre + k].values for k in M31})
                    tb, pb = band31(te, pre), band31(p.add_prefix("p_"), "p_")
                    f1s.append(macro_f1(te[[pre + k for k in M31]].set_axis(M31, axis=1), p, V31_METRICS))
                accs.append((tb == pb).mean())
                kaps.append(cohen_kappa_score(tb, pb))
            base = np.bincount(tb[tb >= 0]).max() / len(tb)
            lines.append(f"| {src} | {len(tr_all):,} | {len(te):,} | {ver} | {base:.3f} | {np.mean(accs):.3f} | {np.mean(kaps):.3f} | {np.mean(f1s):.3f} |")
    lines.append("\n(VulDB's v3.1 row: the same 1,000 CVEs, with their own v3.1 vectors as labels; macro-F1 averaged over the 8 v3.1 metrics.)")


def part_b(df, lines):
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    PIPE.mkdir(parents=True, exist_ok=True)
    f_r, f_n = PIPE / "T2_temporal_pipeline_rule_R.parquet", PIPE / "T2_temporal_pipeline_scsisa_N.parquet"
    if not (f_r.exists() and f_n.exists()):
        v31 = stage1(v31_pool(before_cutoff=True), list(test["text"]))
        convert(v31, True).assign(cve_id=test["cve_id"]).to_parquet(f_r, index=False)
        convert(v31, False).assign(cve_id=test["cve_id"]).to_parquet(f_n, index=False)
    ids = test["cve_id"]
    t = Encoded(test, "y_")

    def enc(path):
        return Encoded(pd.read_parquet(path).set_index("cve_id").loc[ids].reset_index())
    es = {"TF-IDF": [enc(PRED / "T2_temporal_tfidf_lr.parquet")], "pipeline (rule R)": [enc(f_r)], "pipeline (SC/SI/SA=N)": [enc(f_n)],
          "DeBERTa": [enc(ENC / f"T2_temporal_deberta-v3-base_none_e25_cwinv_sqrt_s{s}" / "pred_latent.parquet") for s in range(5)],
          "DeBERTa+auxiliary": [enc(ENC / f"T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s{s}" / "pred_latent.parquet") for s in range(5)]}
    nd = (test["label_type"] != "derived").to_numpy()

    def sc(name, ix):
        rs = [fast_scores(t, e, ix) for e in es[name]]
        return np.array([np.mean([r[k] for r in rs]) for k in KEYS])
    lines += ["\n## B. Complete test set: models that predict v4.0 directly − pipelines without v4.0 labels (paired bootstrap, 1,000 resamples)\n",
              "Point estimates of the pipelines (for checking, should match Table 2): " + "; ".join(
                  f"{n} all {sc(n, np.arange(len(test)))[0]:.3f} / {sc(n, np.arange(len(test)))[1]:.3f}, non-derived {sc(n, np.flatnonzero(nd))[0]:.3f} / {sc(n, np.flatnonzero(nd))[1]:.3f}"
                  for n in ["pipeline (rule R)", "pipeline (SC/SI/SA=N)"]) + " (mean macro-F1 / band accuracy).\n",
              "| A − B | Scope | Mean macro-F1 | Band accuracy | Underestimation |", "|---|---|---|---|---|"]
    for a, b in [("TF-IDF", "pipeline (rule R)"), ("DeBERTa", "pipeline (rule R)"), ("DeBERTa+auxiliary", "pipeline (rule R)"), ("DeBERTa+auxiliary", "pipeline (SC/SI/SA=N)")]:
        for name, idx in [("all", np.arange(len(test))), ("non-derived", np.flatnonzero(nd))]:
            d = sc(a, idx) - sc(b, idx)
            bs = np.array([sc(a, ix) - sc(b, ix) for ix in (rng.choice(idx, size=len(idx), replace=True) for _ in range(1000))])
            lines.append(f"| {a} − {b} | {name} | " + " | ".join(f"{d[j]:+.3f} [{np.percentile(bs[:, j], 2.5):+.3f}, {np.percentile(bs[:, j], 97.5):+.3f}]" for j in range(3)) + " |")


def part_c(df, lines):
    d = df[(df["source"] == "VulnCheck") & df["has_v31"]].copy()
    conv = [rule_convert({k: r["x31_" + k] for k in M31}) for _, r in d.iterrows()]
    d["agree"] = [all(c[k] == r["y_" + k] for k in M40) for c, (_, r) in zip(conv, d.iterrows())]
    d["q"] = d["pub"].dt.tz_localize(None).dt.to_period("Q").astype(str)
    d["old"] = d["cve_id"].str.extract(r"CVE-(\d{4})-")[0].astype(int) <= d["pub"].dt.year - 2
    lines += ["\n## C. VulnCheck's quarterly agreement with rule R: new vulnerabilities and back-filled old ones (identifier year at least two years before the publication year) separately\n",
              "| Quarter | All: n / agreement | New: n / agreement | Back-filled: n / agreement |", "|---|---|---|---|"]
    for q, g in d.groupby("q"):
        if len(g) < 30:
            continue
        cell = lambda x: f"{len(x):,} / {x['agree'].mean():.1%}" if len(x) else "0 / –"  # noqa: E731
        lines.append(f"| {q} | {cell(g)} | {cell(g[~g['old']])} | {cell(g[g['old']])} |")


def part_d(df, lines):
    main = LLM / "deepseek-v4-pro_DTD_s0" / "predictions.parquet"
    ids = pd.read_parquet(main)["cve_id"]
    truth = df.set_index("cve_id").loc[ids].reset_index()
    t = Encoded(truth, "y_")

    def enc(path):
        return Encoded(pd.read_parquet(path).set_index("cve_id").loc[ids].reset_index())
    es = {"DeepSeek": [enc(main)], "Qwen3-8B": [enc(LLM / "Qwen3-8B_DTD_s0" / "predictions.parquet")],
          "majority class": [enc(PRED / "T2_temporal_majority.parquet")], "TF-IDF": [enc(PRED / "T2_temporal_tfidf_lr.parquet")],
          "pipeline (rule R)": [enc(PIPE / "T2_temporal_pipeline_rule_R.parquet")],
          "DeBERTa": [enc(ENC / f"T2_temporal_deberta-v3-base_none_e25_cwinv_sqrt_s{s}" / "pred_latent.parquet") for s in range(5)],
          "DeBERTa+auxiliary": [enc(ENC / f"T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s{s}" / "pred_latent.parquet") for s in range(5)]}
    lt = truth["label_type"].to_numpy()
    types = ["derived", "independent", "v4_only", "other"]
    strata = {ty: np.flatnonzero(lt == ty) for ty in types}

    def sc(ix):
        return {n: np.array([np.mean([fast_scores(t, e, ix)[k] for e in ee]) for k in KEYS[:2]]) for n, ee in es.items()}
    scopes = {"pooled": types, "nd": types[1:]}
    point = {s: sc(np.concatenate([strata[ty] for ty in tys])) for s, tys in scopes.items()}
    boots = []
    for _ in range(1000):
        res = {ty: rng.choice(ix, size=len(ix), replace=True) for ty, ix in strata.items()}  # 两个口径用同一次重抽样
        boots.append({s: sc(np.concatenate([res[ty] for ty in tys])) for s, tys in scopes.items()})
    lines += ["\n## D. All pairwise comparisons on the 2,000-CVE sample: opposite signs of the pooled and the non-derived differences\n",
              "| A − B | Metric | Pooled [95%] | Non-derived [95%] | Opposite signs | Neither interval contains 0 |", "|---|---|---|---|---|---|"]
    n_pairs = n_flip = n_sig = 0
    for a, b in combinations(es, 2):
        for j, key in enumerate(["mean macro-F1", "band accuracy"]):
            n_pairs += 1
            vals = {}
            for s in scopes:
                d = point[s][a][j] - point[s][b][j]
                ci = np.percentile([bb[s][a][j] - bb[s][b][j] for bb in boots], [2.5, 97.5])
                vals[s] = (d, ci)
            flip = vals["pooled"][0] * vals["nd"][0] < 0
            sig = flip and all(ci[0] * ci[1] > 0 for _, ci in vals.values())
            n_flip += flip
            n_sig += sig
            if flip:
                lines.append(f"| {a} − {b} | {key} | " + " | ".join(f"{vals[s][0]:+.3f} [{vals[s][1][0]:+.3f}, {vals[s][1][1]:+.3f}]" for s in scopes) + f" | yes | {'yes' if sig else 'no'} |")
    lines.append(f"\n{n_pairs} (method pair × metric) in total; {n_flip} with opposite signs, of which {n_sig} with neither interval containing 0. Only those with opposite signs are listed.")


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    lines = ["# Further controls (generated automatically)\n"]
    for step in (part_a, part_b, part_c, part_d):
        step(df, lines)
        OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
