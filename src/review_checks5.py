"""Label-substitution control (CPU, a few minutes, no retraining).

Question: is the inflation of evaluation results by derived labels caused by the derivation itself, or by characteristics of the
source VulDB (a narrow range of vulnerability types, templated descriptions)?
Method: keep the CVEs, descriptions, sources and model predictions fixed and change only the reference labels.
  On the dual-scored CVEs of non-derived sources in the temporal split test set, the same predictions are scored against
  (a) the CNA's original v4.0 vector and (b) the v4.0 vector obtained by converting the same CNA's v3.1 vector with rule R
  ("as if these labels were derived"). The difference between the two scores is the change caused by the derivation itself.
  Reported for all of these CVEs, for VulnCheck and without VulnCheck; paired bootstrap with 1,000 resamples.
Output: results/review_checks/summary5.md
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded, fast_scores  # noqa: E402
from baselines_v0 import CUTOFF, M31, M40, evaluate, load, source_type_map  # noqa: E402
from rq1_stats import rule_convert  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
PRED = ROOT / "results" / "baselines_v0" / "predictions"
KEYS = ["mean_macro_f1", "band_acc", "under_rate"]


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    test = df[(df["pub"] >= CUTOFF) & df["has_v31"] & (df["label_type"] != "derived")].reset_index(drop=True)
    conv = [rule_convert({k: r["x31_" + k] for k in M31}) for _, r in test.iterrows()]
    test_r = test.copy()
    for k in M40:
        test_r["y_" + k] = [c[k] for c in conv]
    same = np.array([all(c[k] == test.at[i, "y_" + k] for k in M40) for i, c in enumerate(conv)])
    ids = test["cve_id"]
    models = {"TF-IDF + LR": [pd.read_parquet(PRED / "T2_temporal_tfidf_lr.parquet")],
              "DeBERTa (5 seeds)": [pd.read_parquet(d / "pred_latent.parquet") for d in sorted(ENC.glob("T2_temporal_deberta-v3-base_none_e5_cwinv_sqrt_s[0-9]"))],
              "DeBERTa + v3.1 auxiliary task (5 seeds)": [pd.read_parquet(d / "pred_latent.parquet") for d in sorted(ENC.glob("T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s[0-9]"))],
              "pipeline (TF-IDF, rule R)": None}
    preds = {n: [p.set_index("cve_id").loc[ids].reset_index() for p in ps] for n, ps in models.items() if ps}
    t_orig, t_conv = Encoded(test, "y_"), Encoded(test_r, "y_")
    enc = {n: [Encoded(p) for p in ps] for n, ps in preds.items()}
    vc = (test["source"] == "VulnCheck").to_numpy()
    lines = ["# Label-substitution control (temporal split test set, dual-scored CVEs of non-derived sources; generated automatically)\n",
             f"{len(test):,} CVEs in total (VulnCheck {int(vc.sum()):,}, others {int((~vc).sum()):,}); for {same.mean():.1%} of them the original v4.0 vector already equals the rule-R conversion.",
             "The same predictions are scored against (a) the CNA's original v4.0 labels and (b) the labels obtained by converting the same CNA's v3.1 vectors with rule R. Difference = (b) − (a) (paired bootstrap with 1,000 resamples, 95% interval).\n"]
    rng = np.random.default_rng(0)
    for scope, m in [("all", np.ones(len(test), bool)), ("VulnCheck", vc), ("without VulnCheck", ~vc)]:
        idx = np.flatnonzero(m)
        lines += [f"\n## {scope} (n = {len(idx):,})\n", "| Model | Metric | Against original labels | Against rule-R labels | Difference [95%] |", "|---|---|---|---|---|"]
        for n, es in enc.items():
            def sc(tt, ix):
                rs = [fast_scores(tt, e, ix) for e in es]
                return {k: np.mean([r[k] for r in rs]) for k in KEYS}
            a, b = sc(t_orig, idx), sc(t_conv, idx)
            boots = []
            for _ in range(1000):
                ix = rng.choice(idx, size=len(idx), replace=True)
                x, y = sc(t_orig, ix), sc(t_conv, ix)
                boots.append([y[k] - x[k] for k in KEYS])
            boots = np.array(boots)
            for j, k in enumerate(KEYS):
                lines.append(f"| {n} | {k} | {a[k]:.3f} | {b[k]:.3f} | {b[k] - a[k]:+.3f} [{np.percentile(boots[:, j], 2.5):+.3f}, {np.percentile(boots[:, j], 97.5):+.3f}] |")
        # 逐指标准确率（TF-IDF）
        p = preds["TF-IDF + LR"][0].iloc[idx]
        lines += ["\nTF-IDF per-metric accuracy: original labels → rule-R labels\n", "| " + " | ".join(M40) + " |", "|" + "---|" * len(M40)]
        cells = []
        for k in M40:
            a_o = (p[k].to_numpy() == test["y_" + k].to_numpy()[idx]).mean()
            a_r = (p[k].to_numpy() == test_r["y_" + k].to_numpy()[idx]).mean()
            cells.append(f"{a_o:.3f} → {a_r:.3f}")
        lines.append("| " + " | ".join(cells) + " |")
    out = ROOT / "results" / "review_checks" / "summary5.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
