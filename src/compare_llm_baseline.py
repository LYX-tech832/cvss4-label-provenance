"""Comparison of the LLM baseline with our methods on the same test CVEs (CPU).

Reads the predictions of the AutoCVSS+LLM baseline (output directory of run_autocvss_baseline.py), restricts the test predictions of the
other methods to the same CVEs, computes the metrics with the same evaluate(), and reports them by label type
(derived / independent / v4_only / other).
Sensitivity analysis: the metrics for which the LLM answered DONT_KNOW (or the request failed) are set to the training-set mode
(AutoCVSS itself sets them to the most conservative label).
The LLM sample is stratified by label type, so the "whole sample" rows do not represent the distribution of the test set; the per-type
results are the main ones.
Once the W4 results are available locally (results/encoder/selected_config.json exists), all seeds of the configuration selected on the
validation set are added (averaged).
Output: <LLM run directory>/compare.md
Usage: python src/compare_llm_baseline.py [--llm_dir results/autocvss_baseline/deepseek-v4-pro_DTD_s0]
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import CUTOFF, M40, evaluate, load, source_type_map  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
TYPES = ["derived", "independent", "v4_only", "other"]
V4_SPECIFIC = ["AT", "UI", "SC", "SI", "SA"]
COLS = [("mean_macro_f1", "meanF1"), ("v4_specific_f1", "v4F1"), ("exact_match", "exact"), ("score_mae", "MAE"),
        ("band_acc", "band"), ("under_rate", "under"), ("hc_recall", "HC-rec")]


def other_methods():
    """Methods with saved test predictions on the T2 temporal split: name -> [prediction files] (metrics averaged over seeds when there are several)"""
    m = {"majority class": [ROOT / "results/baselines_v0/predictions/T2_temporal_majority.parquet"],
         "TF-IDF+LR": [ROOT / "results/baselines_v0/predictions/T2_temporal_tfidf_lr.parquet"],
         "TF-IDF+LR (description only, the same input as the LLM)": [ROOT / "results/ablation_desc_only/T2_temporal_tfidf_lr_desc_only.parquet"],
         "DeBERTa (W3, 3 epochs, seed 0)": [ENC / "T2_temporal_deberta-v3-base_none_s0/pred_latent.parquet"],
         "DeBERTa+v3.1 auxiliary (W3, 3 epochs, seed 0)": [ENC / "T2_temporal_deberta-v3-base_none_aux_s0/pred_latent.parquet"]}
    sel = ENC / "selected_config.json"
    if sel.exists():
        for ver, c in json.loads(sel.read_text(encoding="utf-8")).items():
            files = sorted(ENC.glob(c["run"].rsplit("_s", 1)[0] + "_s[0-9]/pred_latent.parquet"))
            if files:
                m[f"DeBERTa{'+v3.1 auxiliary' if ver == 'aux' else ''} (configuration selected in W4, {len(files)} seeds)"] = files
    return {k: [f for f in v if f.exists()] for k, v in m.items() if any(f.exists() for f in v)}


def scores(true_df, pred_df):
    r = evaluate(true_df.reset_index(drop=True), pred_df.reset_index(drop=True))
    r["v4_specific_f1"] = float(np.mean([r["per_metric"][k]["macro_f1"] for k in V4_SPECIFIC]))
    return {k: r[k] for k, _ in COLS}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--llm_dir", default=str(ROOT / "results" / "autocvss_baseline" / "deepseek-v4-pro_DTD_s0"))
    args = ap.parse_args()
    llm_dir = Path(args.llm_dir)
    llm = pd.read_parquet(llm_dir / "predictions.parquet")
    info = json.loads((llm_dir / "results.json").read_text(encoding="utf-8"))

    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    test = df.set_index("cve_id").loc[llm["cve_id"]].reset_index()

    # 敏感性分析：DONT_KNOW / 调用失败 → 训练集众数（只改我们自己的后处理，不重新调用 LLM）
    raw = [json.loads(line) for line in (llm_dir / "raw.jsonl").read_text(encoding="utf-8").splitlines()]
    unknown = {(r["cve_id"], r["metric"]) for r in raw if r["label"] in (None, "DONT_KNOW")}
    train = df[df["pub"] < CUTOFF]
    majority = {k: train["y_" + k].mode()[0] for k in M40}
    alt = llm.copy()
    pos = {c: i for i, c in enumerate(alt["cve_id"])}
    for cve, k in unknown:
        if cve in pos:
            alt.iloc[pos[cve], alt.columns.get_loc(k)] = majority[k]

    preds = {f"AutoCVSS + {info['model']} (DONT_KNOW → most conservative, as in AutoCVSS)": [llm],
             f"AutoCVSS + {info['model']} (DONT_KNOW → training-set mode, sensitivity analysis)": [alt]}
    # 其他大模型（如本地 Qwen3-8B）：必须与主运行是同一批 CVE
    for d in sorted(llm_dir.parent.glob("*_DTD_s0")):
        if d == llm_dir or not (d / "predictions.parquet").exists():
            continue
        o = pd.read_parquet(d / "predictions.parquet")
        if set(o["cve_id"]) != set(llm["cve_id"]):
            print(f"warning: the CVEs of {d.name} differ from the main run; skipped")
            continue
        preds[f"AutoCVSS + {json.loads((d / 'results.json').read_text(encoding='utf-8'))['model']} (as in AutoCVSS)"] = \
            [o.set_index("cve_id").loc[llm["cve_id"]].reset_index()]
    for name, files in other_methods().items():
        preds[name] = [pd.read_parquet(f).set_index("cve_id").loc[test["cve_id"]].reset_index() for f in files]

    lines = [f"# Comparison with the LLM baseline (the same {len(test):,} test CVEs, generated automatically)\n",
             f"- LLM: {info['model']}, AutoCVSS {info['prompt']} prompt (no CoT), thinking mode {info.get('thinking')}; "
             f"package versions {info.get('versions')}",
             f"- Sample stratified by label type: {test['label_type'].value_counts().to_dict()}. "
             "The \"whole sample\" rows do not represent the distribution of the test set; **the per-type results are the main ones**",
             "- All supervised methods are trained only on data from before 2026 (temporal split); the LLM is zero-shot; the W3 DeBERTa runs are single-seed, 3 epochs, untuned",
             f"- Share of DONT_KNOW answers or failed requests (per metric): { {k: round(v, 3) for k, v in info['fallback_rate'].items()} }",
             f"- Token usage: {info.get('usage_total')}\n",
             "| Scope | Method | " + " | ".join(c for _, c in COLS) + " |",
             "|---|---|" + "---|" * len(COLS)]
    for scope in ["whole sample"] + TYPES:
        m = np.ones(len(test), bool) if scope == "whole sample" else (test["label_type"] == scope).values
        if m.sum() < 30:
            continue
        for name, plist in preds.items():
            rs = [scores(test[m], p[m]) for p in plist]
            avg = {k: float(np.mean([r[k] for r in rs])) for k, _ in COLS}
            lines.append(f"| {scope} (n={m.sum()}) | {name} | " + " | ".join(f"{avg[k]:.3f}" for k, _ in COLS) + " |")
    out = llm_dir / "compare.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nwritten to {out}")


if __name__ == "__main__":
    main()
