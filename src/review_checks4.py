"""Check (CPU, a few minutes): is the transfer gain only the learning of rule R's conversion convention?

Compares the variants on two subsets where rule R cannot help:
- R-inconsistent subset: dual-scored temporal split test CVEs whose v4.0 vector differs from rule R(same-source v3.1) (2,602 CVEs);
- test CVEs without a same-source v3.1 vector (their v4.0 labels cannot be compared with rule R).
Variants: baseline / v3.1 auxiliary task (5 epochs, seeds 0-4; 10 epochs, seeds 0-2), pseudo-labels, DeBERTa pipeline (seeds 0-2),
TF-IDF. Differences: paired bootstrap (test CVEs resampled 1,000 times, each variant averaged over its seeds).
Output: results/review_checks/summary4.md
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded, fast_scores  # noqa: E402
from baselines_v0 import CUTOFF, M40, evaluate, load, source_type_map  # noqa: E402
from review_checks import clean_mask  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
STEM = "T2_temporal_deberta-v3-base_none"
VERS = {"baseline 5 epochs": ("_e5_cwinv_sqrt", range(5)), "v3.1 auxiliary 5 epochs": ("_aux_e5_cwinv_sqrt", range(5)),
        "baseline 10 epochs": ("_e10_cwinv_sqrt", range(3)), "v3.1 auxiliary 10 epochs": ("_aux_e10_cwinv_sqrt", range(3)),
        "pseudo-labels 5 epochs": ("_pseudo_e5_cwinv_sqrt", range(3)), "DeBERTa pipeline": ("_v31only_e5", range(3))}
SHARED = ["AV", "AC", "PR", "UI", "VC", "VI", "VA"]


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    test["clean"] = clean_mask(test)
    ids = test["cve_id"]
    t = Encoded(test, "y_")
    preds = {v: [pd.read_parquet(ENC / f"{STEM}{tag}_s{s}" / "pred_latent.parquet").set_index("cve_id").loc[ids].reset_index() for s in seeds]
             for v, (tag, seeds) in VERS.items()}
    preds["TF-IDF"] = [pd.read_parquet(ROOT / "results" / "baselines_v0" / "predictions" / "T2_temporal_tfidf_lr.parquet").set_index("cve_id").loc[ids].reset_index()]
    enc = {v: [Encoded(p) for p in ps] for v, ps in preds.items()}
    subsets = {"all (21,900)": np.ones(len(test), bool), "R-inconsistent subset": test["clean"].to_numpy(),
               "no same-source v3.1": (~test["has_v31"]).to_numpy(),
               "R-inconsistent subset without VulnCheck": (test["clean"] & (test["source"] != "VulnCheck")).to_numpy()}
    lines = ["# Transfer gains on subsets where rule R cannot help (temporal split; generated automatically)\n",
             "R-inconsistent subset = dual-scored and v4.0 ≠ rule R(same-source v3.1); of these, VulnCheck "
             f"{int((test['clean'] & (test['source'] == 'VulnCheck')).sum()):,}, derived {int((test['clean'] & (test['label_type'] == 'derived')).sum())}.\n"]
    for name, m in subsets.items():
        idx = np.flatnonzero(m)
        lines += [f"\n## {name}: n = {len(idx):,}\n", "| Variant | Seeds | Mean macro-F1 | Macro-F1 of the 7 shared metrics | Macro-F1 of AT/SC/SI/SA | Band accuracy |", "|---|---|---|---|---|---|"]
        tt = test.iloc[idx].reset_index(drop=True)
        for v, ps in preds.items():
            rs = [evaluate(tt, p.iloc[idx].reset_index(drop=True)) for p in ps]
            sh = np.mean([np.mean([r["per_metric"][k]["macro_f1"] for k in SHARED]) for r in rs])
            nw = np.mean([np.mean([r["per_metric"][k]["macro_f1"] for k in ["AT", "SC", "SI", "SA"]]) for r in rs])
            lines.append(f"| {v} | {len(ps)} | {np.mean([r['mean_macro_f1'] for r in rs]):.3f} | {sh:.3f} | {nw:.3f} | {np.mean([r['band_acc'] for r in rs]):.3f} |")
        rng = np.random.default_rng(0)
        lines += ["\nPaired bootstrap (A − B, mean macro-F1 / band accuracy, 95% interval; when the two variants have different numbers of seeds, only the common seeds 0–2 are used):\n", "| A − B | Mean macro-F1 difference | Band accuracy difference |", "|---|---|---|"]
        for a, b in [("v3.1 auxiliary 5 epochs", "baseline 5 epochs"), ("v3.1 auxiliary 10 epochs", "baseline 10 epochs"), ("pseudo-labels 5 epochs", "baseline 5 epochs"),
                     ("v3.1 auxiliary 5 epochs", "pseudo-labels 5 epochs"), ("DeBERTa pipeline", "baseline 5 epochs")]:
            k = min(len(enc[a]), len(enc[b]))  # 种子数不同时只比较共同的种子（都从 0 开始）

            def d(ix):
                fa = [fast_scores(t, e, ix) for e in enc[a][:k]]
                fb = [fast_scores(t, e, ix) for e in enc[b][:k]]
                return (np.mean([x["mean_macro_f1"] for x in fa]) - np.mean([x["mean_macro_f1"] for x in fb]),
                        np.mean([x["band_acc"] for x in fa]) - np.mean([x["band_acc"] for x in fb]))
            pt = d(idx)
            bs = np.array([d(rng.choice(idx, size=len(idx), replace=True)) for _ in range(1000)])
            lines.append(f"| {a} − {b} | {pt[0]:+.3f} [{np.percentile(bs[:, 0], 2.5):+.3f}, {np.percentile(bs[:, 0], 97.5):+.3f}] | "
                         f"{pt[1]:+.3f} [{np.percentile(bs[:, 1], 2.5):+.3f}, {np.percentile(bs[:, 1], 97.5):+.3f}] |")
    # AT：干净子集中真实值为 AT:Present 的样本，各模型预测成默认值 None 的比例，以及干净子集上 AT 的宏 F1
    from aggregate_seeds import paired_bootstrap  # noqa: E402
    preds["5% + v3.1 auxiliary"] = [pd.read_parquet(ENC / f"{STEM}_aux_e5_cwinv_sqrt_frac0.05_s{s}" / "pred_latent.parquet").set_index("cve_id").loc[ids].reset_index()
                                for s in range(3)]
    cm = test["clean"].to_numpy()
    atp = cm & (test["y_AT"] == "P").to_numpy()
    lines += [f"\n## AT: the {int(atp.sum()):,} labels of the R-inconsistent subset with AT:Present\n", "| Variant | Seeds | Share predicted as AT:None | Macro-F1 of AT on the R-inconsistent subset |", "|---|---|---|---|"]
    ct = test[cm].reset_index(drop=True)
    for v, ps in preds.items():
        share = np.mean([(p["AT"].to_numpy()[atp] == "N").mean() for p in ps])
        f1 = np.mean([evaluate(ct, p[cm].reset_index(drop=True))["per_metric"]["AT"]["macro_f1"] for p in ps])
        lines.append(f"| {v} | {len(ps)} | {share:.3f} | {f1:.3f} |")
    # 5% + 辅助 与训练 10 轮、用全部标签的无辅助模型：按子集比较（复用 paired_bootstrap 的"非 derived"口径来指定子集）
    rconv = test["has_v31"].to_numpy() & ~cm & (test["label_type"] != "derived").to_numpy()
    lines += ["\n## 5% + auxiliary − all labels, baseline (10 epochs): mean macro-F1 difference (paired bootstrap, 1,000 resamples)\n", "| Subset | n | Difference [95%] |", "|---|---|---|"]
    none10 = {s: ENC / f"{STEM}_e10_cwinv_sqrt_s{s}" for s in range(3)}
    aux5p = {s: ENC / f"{STEM}_aux_e5_cwinv_sqrt_frac0.05_s{s}" for s in range(3)}
    for name, m in [("R-inconsistent subset", cm), ("consistent with rule R (dual-scored, non-derived)", rconv),
                    ("consistent with rule R (dual-scored, including derived)", test["has_v31"].to_numpy() & ~cm)]:
        keep = set(test["cve_id"][m])
        sub = df.assign(label_type=np.where(df["cve_id"].isin(keep), "keep", "derived"))
        r = paired_bootstrap(sub, none10, aux5p)["non_derived"]
        lines.append(f"| {name} | {r['n']:,} | {r['mean_macro_f1'][0]:+.3f} [{r['mean_macro_f1'][1]:+.3f}, {r['mean_macro_f1'][2]:+.3f}] |")
    out = ROOT / "results" / "review_checks" / "summary4.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
