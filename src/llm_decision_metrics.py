"""Decision-oriented metrics on the LLM sample, and an example of derived labels (CPU, about 2 minutes):

1. Underestimation rate and High+Critical recall of each method on the LLM sample (2,000 CVEs), for the whole sample, the non-derived
   labels and the four label types (Table S37; Section 7.5). Mean macro-F1 and band accuracy are also written, to check that they
   match Table 4.
2. An example of derived labels: how many distinct v4.0 vectors correspond to VulDB's most frequent v3.1 vectors, compared with
   VulnCheck (Section 4.3).
Output: results/review_checks/summary14.md
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import CUTOFF, M31, M40, evaluate, load, source_type_map  # noqa: E402
from rq1_stats import rule_convert  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
LLM = ROOT / "results" / "autocvss_baseline"
OUT = ROOT / "results" / "review_checks" / "summary14.md"
STEM = "T2_temporal_deberta-v3-base_none"
SCOPES = [("whole sample", None), ("non-derived", "nd"), ("derived", "derived"), ("undetected", "independent"), ("v4-only", "v4_only"), ("other", "other")]


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    main_dir = LLM / "deepseek-v4-pro_DTD_s0"
    llm = pd.read_parquet(main_dir / "predictions.parquet")
    ids = llm["cve_id"]
    test = df.set_index("cve_id").loc[ids].reset_index()
    lt = test["label_type"].to_numpy()

    # "don't know" → 训练集众数（与 compare_llm_baseline.py 相同的后处理）
    raw = [json.loads(line) for line in (main_dir / "raw.jsonl").read_text(encoding="utf-8").splitlines()]
    unknown = {(r["cve_id"], r["metric"]) for r in raw if r["label"] in (None, "DONT_KNOW")}
    train = df[df["pub"] < CUTOFF]
    majority = {k: train["y_" + k].mode()[0] for k in M40}
    alt = llm.copy()
    pos = {c: i for i, c in enumerate(alt["cve_id"])}
    for cve, k in unknown:
        if cve in pos:
            alt.iloc[pos[cve], alt.columns.get_loc(k)] = majority[k]

    def rd(p):
        return pd.read_parquet(p).set_index("cve_id").loc[ids].reset_index()

    methods = [("AutoCVSS + DeepSeek-V4-Pro", [llm]),
               ("– \"don't know\" → training-set mode", [alt]),
               ("AutoCVSS + Qwen3-8B", [rd(LLM / "Qwen3-8B_DTD_s0" / "predictions.parquet")]),
               ("majority class", [rd(ROOT / "results/baselines_v0/predictions/T2_temporal_majority.parquet")]),
               ("TF-IDF + LR", [rd(ROOT / "results/baselines_v0/predictions/T2_temporal_tfidf_lr.parquet")]),
               ("TF-IDF + LR (description only)", [rd(ROOT / "results/ablation_desc_only/T2_temporal_tfidf_lr_desc_only.parquet")]),
               ("DeBERTa (25 epochs, 5 seeds)", [rd(ENC / f"{STEM}_e25_cwinv_sqrt_s{s}" / "pred_latent.parquet") for s in range(5)]),
               ("DeBERTa + v3.1 auxiliary task (5 seeds)", [rd(ENC / f"{STEM}_aux_e5_cwinv_sqrt_s{s}" / "pred_latent.parquet") for s in range(5)])]

    res = {}
    for name, plist in methods:
        for scope, key in SCOPES:
            m = np.ones(len(test), bool) if key is None else (lt != "derived") if key == "nd" else (lt == key)
            rs = [evaluate(test[m].reset_index(drop=True), p[m].reset_index(drop=True)) for p in plist]
            res[(name, scope)] = {k: float(np.mean([r[k] for r in rs])) for k in ("mean_macro_f1", "band_acc", "under_rate", "hc_recall")}
    n = {scope: int((np.ones(len(test), bool) if key is None else (lt != "derived") if key == "nd" else (lt == key)).sum()) for scope, key in SCOPES}
    head = "| Method | " + " | ".join(f"{s} ({n[s]:,})" for s, _ in SCOPES) + " |"
    lines = ["# Decision-oriented metrics on the LLM sample, and an example of derived labels (generated automatically)\n",
             "## 1. Underestimation rate / High+Critical recall (LLM sample, 2,000 CVEs; DeBERTa averaged over 5 seeds) → Table S37\n", head, "|---|" + "---|" * len(SCOPES)]
    for name, _ in methods:
        lines.append(f"| {name} | " + " | ".join(f"{res[(name, s)]['under_rate']:.3f} / {res[(name, s)]['hc_recall']:.3f}" for s, _ in SCOPES) + " |")
    lines += ["\nFor checking: mean macro-F1 / band accuracy (should match Table 4 of the paper)\n", head, "|---|" + "---|" * len(SCOPES)]
    for name, _ in methods:
        lines.append(f"| {name} | " + " | ".join(f"{res[(name, s)]['mean_macro_f1']:.3f} / {res[(name, s)]['band_acc']:.3f}" for s, _ in SCOPES) + " |")

    # 2 例子
    d = df[df["has_v31"]].copy()
    d["v31"] = d[["x31_" + k for k in M31]].apply(lambda r: "/".join(f"{k}:{v}" for k, v in zip(M31, r)), axis=1)
    d["v40"] = d[["y_" + k for k in M40]].apply(lambda r: "/".join(f"{k}:{v}" for k, v in zip(M40, r)), axis=1)
    vul = d[d["source"] == "VulDB"]
    top = vul["v31"].value_counts()
    lines += ["\n## 2. An example of derived labels (all CVEs with a same-source v3.1 vector) → Section 4.3\n",
              "| Source | v3.1 vector | CVEs | Distinct v4.0 vectors | Most frequent v4.0 vector | Its count (share) | Result of rule R |", "|---|---|---|---|---|---|---|"]
    for v31 in top.index[:3]:
        r = rule_convert(dict(kv.split(":") for kv in v31.split("/")))
        rule = "/".join(f"{k}:{r[k]}" for k in M40)
        for src in ["VulDB", "VulnCheck", "GitHub_M"]:
            sub = d[(d["source"] == src) & (d["v31"] == v31)]
            if len(sub) == 0:
                lines.append(f"| {src} | {v31} | 0 | – | – | – | {rule} |")
                continue
            vc = sub["v40"].value_counts()
            lines.append(f"| {src} | {v31} | {len(sub):,} | {len(vc)} | {vc.index[0]} | {vc.iloc[0]:,} ({vc.iloc[0] / len(sub):.1%}) | {rule} |")
    lines.append(f"\nVulDB has {len(vul):,} CVEs with a same-source v3.1 vector: {vul['v31'].nunique()} distinct v3.1 vectors and {vul['v40'].nunique()} distinct v4.0 vectors.")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nwritten to {OUT}")


if __name__ == "__main__":
    main()
