"""Sensitivity analyses (CPU).

(a) Threshold of the source typing: FD_oos thresholds 0.80 / 0.90 (main setting) / 0.95 (all on data before 2026), plus a typing on a
    recent window (FD_oos computed on 2025 data only, threshold 0.95). Under each typing:
    - evaluation inflation: difference between all test labels and the labels without derived ones, for T2 TF-IDF+LR and T1 rule R;
    - LLM comparison: the methods on the derived and the non-derived groups of the same 2,000 CVEs.
(b) Definition of the per-group macro-F1: evaluate() uses the full label set (a class absent from both labels and predictions scores 0);
    the alternative uses the sklearn default (only classes present in the labels or predictions). Checks whether the conclusions change.
Output: results/sensitivity/summary.md
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import CUTOFF, M40, evaluate, load  # noqa: E402
from cvss_utils import V40_METRICS  # noqa: E402
from label_provenance import analyse, collect  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
PRED = ROOT / "results" / "baselines_v0" / "predictions"
OUT = ROOT / "results" / "sensitivity"
LLM_DIR = ROOT / "results" / "autocvss_baseline" / "deepseek-v4-pro_DTD_s0"
TYPES = ["derived", "independent", "v4_only", "other"]


def mean_f1(true_df, pred_df, full_labels=True):
    vals = []
    for k in M40:
        t, p = true_df["y_" + k].values, pred_df[k].values
        vals.append(f1_score(t, p, average="macro", labels=V40_METRICS[k] if full_labels else None, zero_division=0))
    return float(np.mean(vals))


def aligned(path, ids):
    return pd.read_parquet(path).set_index("cve_id").loc[ids].reset_index()


def row(name, t, p):
    r = evaluate(t.reset_index(drop=True), p.reset_index(drop=True))
    return (f"| {name} (n={len(t):,}) | {r['mean_macro_f1']:.3f} | {mean_f1(t, p, False):.3f} | {r['exact_match']:.3f} "
            f"| {r['band_acc']:.3f} | {r['under_rate']:.3f} |")


def main():
    df = load()
    types = json.loads((ROOT / "results" / "label_provenance" / "source_types.json").read_text(encoding="utf-8"))
    fd_pre = {s: v["FD_oos_pre2026"] for s, v in types.items() if "FD_oos_pre2026" in v}
    start25 = CUTOFF - pd.DateOffset(years=1)
    pairs25 = collect(df[(df["pub"] >= start25) & (df["pub"] < CUTOFF)])
    fd_25 = {s: analyse(p)["FD_oos"] for s, p in pairs25.items() if len(p) >= 100}
    typings = {"threshold 0.80": {s for s, v in fd_pre.items() if v >= 0.80},
               "threshold 0.90 (main setting)": {s for s, v in fd_pre.items() if v >= 0.90},
               "threshold 0.95": {s for s, v in fd_pre.items() if v >= 0.95},
               "recent window (2025 data, threshold 0.95)": {s for s, v in fd_25.items() if v >= 0.95}}

    lines = ["# Sensitivity analyses (generated automatically)\n", "## (a) Threshold of the source typing\n",
             "Out-of-sample functional dependence FD_oos of each source (all data before 2026 / 2025 data only; sources with at least 100 pairs):\n",
             "| Source | FD_oos (before 2026) | FD_oos (2025) |", "|---|---|---|"]
    for s in sorted(set(fd_pre) | set(fd_25), key=lambda s: -fd_pre.get(s, fd_25.get(s, 0))):
        a, b = fd_pre.get(s), fd_25.get(s)
        lines.append(f"| {s} | {'—' if a is None else f'{a:.1%}'} | {'—' if b is None else f'{b:.1%}'} |")
    lines += ["", "Sources typed as derived under each typing: " + "; ".join(f"{k}: {', '.join(sorted(v)) or 'none'}" for k, v in typings.items()), ""]

    t2 = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    t1 = df[df["has_v31"] & (df["pub"] >= CUTOFF)].reset_index(drop=True)
    tfidf, rule = aligned(PRED / "T2_temporal_tfidf_lr.parquet", t2["cve_id"]), aligned(PRED / "T1_temporal_rule_R.parquet", t1["cve_id"])
    lines += ["### Evaluation inflation: all test labels vs without derived\n",
              "| Typing / setting / scope | Mean macro-F1 (full label set) | Mean macro-F1 (sklearn default) | Exact vector | Band accuracy | Underestimation |",
              "|---|---|---|---|---|---|"]
    lines.append(row("T2 TF-IDF+LR, all", t2, tfidf))
    lines.append(row("T1 rule R, all", t1, rule))
    for name, der in typings.items():
        if not der:
            lines.append(f"| {name}: no source typed as derived, no distinction possible | | | | | |")
            continue
        m2, m1 = ~t2["source"].isin(der).values, ~t1["source"].isin(der).values
        lines.append(row(f"{name}, T2 TF-IDF+LR, without derived", t2[m2], tfidf[m2]))
        lines.append(row(f"{name}, T1 rule R, without derived", t1[m1], rule[m1]))

    # 大模型对比（同一批 2,000 条）：derived vs 非 derived
    llm = pd.read_parquet(LLM_DIR / "predictions.parquet")
    s = df.set_index("cve_id").loc[llm["cve_id"]].reset_index()
    # 每个方法是一组预测（多个种子时指标按种子取平均）；DeBERTa 用 W4 选定配置的全部种子，与表 9 同一口径
    w4 = sorted((ROOT / "results/encoder").glob("T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s[0-9]/pred_latent.parquet"))
    methods = {"AutoCVSS + DeepSeek": [llm.set_index("cve_id").loc[s["cve_id"]].reset_index()],
               "TF-IDF+LR": [aligned(PRED / "T2_temporal_tfidf_lr.parquet", s["cve_id"])],
               "TF-IDF+LR (description only)": [aligned(ROOT / "results/ablation_desc_only/T2_temporal_tfidf_lr_desc_only.parquet", s["cve_id"])],
               f"DeBERTa+auxiliary (W4, {len(w4)} seeds)": [aligned(f, s["cve_id"]) for f in w4]}
    avg = lambda ps, fn: float(np.mean([fn(p) for p in ps]))  # noqa: E731
    lines += ["\n### LLM comparison (the same 2,000 CVEs): derived and non-derived groups under each typing\n",
              "Each cell: mean macro-F1 (full label set) / mean macro-F1 (sklearn default) / band accuracy\n",
              "| Typing | Group | " + " | ".join(methods) + " |", "|---|---|" + "---|" * len(methods)]
    for name, der in typings.items():
        for grp, m in [("derived", s["source"].isin(der).values), ("non-derived", ~s["source"].isin(der).values)]:
            if m.sum() < 30:
                continue
            cells = []
            for ps in methods.values():
                rs = [evaluate(s[m].reset_index(drop=True), p[m].reset_index(drop=True)) for p in ps]
                cells.append(f"{np.mean([r['mean_macro_f1'] for r in rs]):.3f} / {avg(ps, lambda p: mean_f1(s[m], p[m], False)):.3f} / "
                             f"{np.mean([r['band_acc'] for r in rs]):.3f}")
            lines.append(f"| {name} | {grp} (n={m.sum()}) | " + " | ".join(cells) + " |")

    # ② 口径：主设定的四个标签类型，看方法排名是否改变
    s["label_type"] = s["source"].map({k: v["type"] for k, v in types.items()}).fillna("other")
    lines += ["\n## (b) Definition of the per-group macro-F1 (main typing, the same 2,000 CVEs)\n",
              "| Label type | Definition | " + " | ".join(methods) + " | Ranking (high → low) |", "|---|---|" + "---|" * (len(methods) + 1)]
    for t in TYPES:
        m = (s["label_type"] == t).values
        for full, lab in [(True, "full label set"), (False, "sklearn default")]:
            vals = {n: avg(ps, lambda p: mean_f1(s[m], p[m], full)) for n, ps in methods.items()}
            rank = " > ".join(n for n, _ in sorted(vals.items(), key=lambda kv: -kv[1]))
            lines.append(f"| {t} (n={m.sum()}) | {lab} | " + " | ".join(f"{v:.3f}" for v in vals.values()) + f" | {rank} |")

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
