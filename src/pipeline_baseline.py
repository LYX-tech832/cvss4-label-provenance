"""Pipeline baseline (CPU): description -> v3.1 (text classification) -> v4.0 (rule-based conversion), following the idea of
Vieira et al., IoT 39 (2026) 102038.

This route uses no v4.0 labels at all; stage 1 is trained only on CVEs that have v3.1 labels only.
Stage 1: TF-IDF + LR, trained on the CVEs with a v3.1 vector and no CNA-provided v4.0 vector
         (temporal split: only those published before 2026; leave-one-source-out: without the CVEs of the held-out source)
Stage 2: two conversion rules
         rule_R          our rule R: AV/AC/PR copied, AT=N, UI: N->N, R->P, VC/VI/VA = C/I/A, SC/SI/SA copied from C/I/A when S:C
         vieira_like     as R, but SC/SI/SA always N (Vieira et al. state that their deterministic mapping sets these three to N)
         Vieira et al.'s pipeline then selects the severity band with a learned model on candidate scores and outputs only the band,
         which cannot be reproduced vector by vector, so this is an approximation.
Evaluation: the same test sets as T2, reported on all labels, without derived labels, and by label type
Output: results/pipeline_baseline/summary.md, metrics.json
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import CUTOFF, M31, M40, SEED, SHORT, evaluate, load, source_type_map  # noqa: E402
from pilot_transfer import v31_pool  # noqa: E402
from rq1_stats import rule_convert  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "results" / "pipeline_baseline"
SPLITS = ["temporal", "loso:VulnCheck", "loso:GitHub_M", "loso:VulDB"]


def stage1(pool, texts):
    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=3, max_features=300_000, sublinear_tf=True)
    x, xq = vec.fit_transform(pool["text"]), vec.transform(texts)
    out = {}
    for k in M31:
        out[k] = LogisticRegression(C=4.0, max_iter=3000, random_state=SEED).fit(x, pool["z_" + k].values).predict(xq)
        print("  stage 1 done for metric", k, flush=True)
    return pd.DataFrame(out)


def convert(v31_df, subsequent_from_scope):
    rows = []
    for _, r in v31_df.iterrows():
        v4 = rule_convert({k: r[k] for k in M31})
        if not subsequent_from_scope:
            v4.update({"SC": "N", "SI": "N", "SA": "N"})
        rows.append(v4)
    return pd.DataFrame(rows)[M40]


def report(test, pred):
    types = test["source"].map(source_type_map()).fillna("other").values
    out = {}
    for scope, m in [("all", np.ones(len(test), bool)), ("non_derived", types != "derived")] + [(t, types == t) for t in ["derived", "independent", "v4_only", "other"]]:
        if m.sum() >= 30:
            r = evaluate(test[m].reset_index(drop=True), pred[m].reset_index(drop=True))
            out[scope] = {k: r[k] for k in SHORT} | {
                "v4_specific_f1": float(np.mean([r["per_metric"][k]["macro_f1"] for k in ["AT", "UI", "SC", "SI", "SA"]]))}
    return out


def main():
    df = load()
    results = {}
    for split in SPLITS:
        if split == "temporal":
            test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
            pool = v31_pool(before_cutoff=True)
        else:
            s = split.split(":", 1)[1]
            test = df[df["source"] == s].reset_index(drop=True)
            pool = v31_pool(before_cutoff=False)
            pool = pool[pool["cna_short_name"].fillna("UNKNOWN") != s]
        print(f"== {split}: stage 1 trained on {len(pool):,} CVEs, {len(test):,} test CVEs", flush=True)
        v31_pred = stage1(pool, list(test["text"]))
        results[split] = {"n_pool": len(pool), "n_test": len(test)}
        for name, sub in [("rule_R", True), ("vieira_like", False)]:
            results[split][name] = report(test, convert(v31_pred, sub))
            a = results[split][name]["all"]
            print(f"  {name}: mean F1 {a['mean_macro_f1']:.3f} exact {a['exact_match']:.3f} band accuracy {a['band_acc']:.3f} underestimation {a['under_rate']:.3f}", flush=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "metrics.json").write_text(json.dumps(results, indent=1, ensure_ascii=False), encoding="utf-8")
    lines = ["# Pipeline baseline: description -> v3.1 (TF-IDF+LR) -> v4.0 (rule-based conversion); no v4.0 labels used\n",
             "Cell = mean F1 / exact / band accuracy / underestimation rate\n",
             "| Split | Conversion | All | Without derived | independent | v4_only | other |", "|---|---|---|---|---|---|---|"]
    for split, r in results.items():
        for name in ["rule_R", "vieira_like"]:
            cells = []
            for scope in ["all", "non_derived", "independent", "v4_only", "other"]:
                x = r[name].get(scope)
                cells.append(f"{x['mean_macro_f1']:.3f} / {x['exact_match']:.3f} / {x['band_acc']:.3f} / {x['under_rate']:.3f}" if x else "-")
            lines.append(f"| {split} | {name} | " + " | ".join(cells) + " |")
    (OUT_DIR / "summary.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
