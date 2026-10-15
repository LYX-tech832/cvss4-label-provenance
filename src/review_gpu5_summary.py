"""Summary of further GPU runs (scripts/run_review_gpu5.sh; CPU, about 20 minutes). Parts without results are marked and skipped, so
the summary can be produced while runs are still going.

1. D0/D1: with the step-matched baselines added as candidate configurations on the leave-one-source-out splits, each split selects its
   configuration again on its own validation set; differences auxiliary − baseline for the selected configurations (common seeds), and
   auxiliary − step-matched baseline (even if it is not selected).
2. A: sequential fine-tuning baseline (temporal split): validation scores of the three caps on the second-stage epochs and the selected
   configuration; compared with the auxiliary task and the 25-epoch baseline (seeds 0-2).
3. B: shuffled-label control on the leave-one-source-out splits: correct labels − shuffled labels; shuffled labels − selected baseline
   configuration (seeds 0-2).
4. C: the earliest 5% of the v4 labels: auxiliary vs baseline (50 epochs); next to the results for a random 5%.
Output: results/review_gpu/summary5.md
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import CUTOFF, load, source_type_map  # noqa: E402
from review_gpu4_summary import ENC, compare, describe, run_dirs, tag_of  # noqa: E402
from select_loso_config import NONE_LOSO_EXTRA, select  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "review_gpu" / "summary5.md"
LOSO = ["loso:VulnCheck", "loso:GitHub_M", "loso:VulDB"]
SHOW = [("mean_macro_f1", "Mean macro-F1"), ("band_acc", "Band accuracy"), ("under_rate", "Underestimation"), ("hc_recall", "H+C recall")]


def val_and_epoch(split, tag, seed=0):
    f = ENC / f"T2_{split.replace(':', '-')}_deberta-v3-base_none{tag}_s{seed}" / "results.json"
    if not f.exists():
        return None
    r = json.loads(f.read_text(encoding="utf-8"))
    return r["val_best_mean_f1"], r["best_epoch"] + 1


def table(lines, df, rows, scopes):
    """rows: [(name, {seed: directory})]; one row per scope."""
    lines += ["| Model | Seeds | Scope | " + " | ".join(n for _, n in SHOW) + " |", "|---|---|---|" + "---|" * len(SHOW)]
    for name, dirs in rows:
        if not dirs:
            lines.append(f"| {name} | — | — | " + " | ".join("no results yet" for _ in SHOW) + " |")
            continue
        for scope in scopes:
            m = describe(dirs, df, scope)
            lines.append(f"| {name} | {sorted(dirs)} | {scope} | " + " | ".join(f"{m[k][0]:.3f} ± {m[k][1]:.3f}" for k, _ in SHOW) + " |")


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    lines = ["# Step-matched baselines on the leave-one-source-out splits, sequential fine-tuning, shuffled-label control and the earliest 5% of the labels (GPU runs; generated automatically)\n"]

    # ---------- 1. 留一来源划分：步数相当的无辅助基线 ----------
    sel = select()
    lines += ["## 1. Leave-one-source-out splits: step-matched baselines (D0 / D1)\n",
              "| Split | Candidate configurations (mean validation macro-F1, seed 0) | Selected baseline configuration | Best epoch of the step-matched candidate |", "|---|---|---|---|"]
    for sp in LOSO:
        sc = sel[sp]["none"]["scores"]
        extra = next(iter(NONE_LOSO_EXTRA[sp]))
        ve = val_and_epoch(sp, extra)
        lines.append(f"| {sp} | " + "; ".join(f"`{t}` {'—' if s is None else f'{s:.4f}'}" for t, s in sc.items())
                     + f" | `{sel[sp]['none']['best']}`{'' if sel[sp]['none']['complete'] else ' (candidates incomplete)'} | {ve[1] if ve else '—'} |")
    for sp in LOSO:
        extra = next(iter(NONE_LOSO_EXTRA[sp]))
        ta, tn = tag_of(sel[sp]["aux"]["args"]), tag_of(sel[sp]["none"]["args"])
        d_aux, d_sel, d_extra = run_dirs(sp, ta), run_dirs(sp, tn), run_dirs(sp, extra)
        lines.append(f"\n### {sp}\n")
        table(lines, df, [(f"auxiliary `{ta}`", d_aux), (f"baseline (selected) `{tn}`", d_sel), (f"baseline (step-matched) `{extra}`", d_extra)], ["all"])
        if d_extra:
            compare(lines, df, f"{sp}: auxiliary − baseline (step-matched)", d_aux, d_extra, ["all"])
        if tn != extra:
            compare(lines, df, f"{sp}: auxiliary − baseline (selected)", d_aux, d_sel, ["all"])

    # ---------- 2. 顺序微调 ----------
    lines += ["\n## 2. Sequential fine-tuning baseline (A; temporal split)\n", "Stage 1: the v3.1 heads are trained for 5 epochs on the 60,000 samples of the v3.1 pool only (as in the DeBERTa pipeline), and the encoder of the best validation epoch is kept; "
              "stage 2: starting from this encoder, fine-tuning on the v4 labels only (class weighting).\n", "| Cap on stage-2 epochs | Mean validation macro-F1 (seed 0) | Best epoch |", "|---|---|---|"]
    vals = {e: val_and_epoch("temporal", f"_e{e}_cwinv_sqrt_seq") for e in (5, 10, 25)}
    for e, v in vals.items():
        lines.append(f"| {e} | {'—' if v is None else f'{v[0]:.4f}'} | {'—' if v is None else v[1]} |")
    if all(v is not None for v in vals.values()):
        best = max(vals, key=lambda e: vals[e][0])
        seq = run_dirs("temporal", f"_e{best}_cwinv_sqrt_seq", range(3))
        aux, none25 = run_dirs("temporal", "_aux_e5_cwinv_sqrt", range(3)), run_dirs("temporal", "_e25_cwinv_sqrt", range(3))
        pseudo = run_dirs("temporal", "_pseudo_e5_cwinv_sqrt", range(3))
        lines.append(f"\nSelected on the validation set: {best} epochs.\n")
        table(lines, df, [("baseline 25 epochs", none25), (f"sequential fine-tuning (stage 2, {best} epochs)", seq), ("v3.1 auxiliary 5 epochs", aux), ("rule-R pseudo-labels 5 epochs", pseudo)], ["all", "non_derived"])
        compare(lines, df, "auxiliary − sequential fine-tuning", aux, seq, ["all", "non_derived"])
        compare(lines, df, "sequential fine-tuning − baseline 25 epochs", seq, none25, ["all", "non_derived"])
    else:
        lines.append("\nThe three stage-2 configurations are not all finished yet.")

    # ---------- 3. 留一来源划分上的打乱标签对照 ----------
    lines.append("\n## 3. Shuffled-label control on the leave-one-source-out splits (B; seeds 0–2)\n")
    for sp in LOSO:
        ta, tn = tag_of(sel[sp]["aux"]["args"]), tag_of(sel[sp]["none"]["args"])
        ts = ta.replace("_aux", "_auxshuf", 1)
        d_aux, d_shuf, d_none = run_dirs(sp, ta, range(3)), run_dirs(sp, ts, range(3)), run_dirs(sp, tn, range(3))
        lines.append(f"\n### {sp}\n")
        table(lines, df, [(f"baseline (selected) `{tn}`", d_none), (f"shuffled v3.1 labels `{ts}`", d_shuf), (f"correct v3.1 labels `{ta}`", d_aux)], ["all"])
        if d_shuf:
            compare(lines, df, f"{sp}: correct labels − shuffled labels", d_aux, d_shuf, ["all"])
            compare(lines, df, f"{sp}: shuffled labels − baseline (selected)", d_shuf, d_none, ["all"])

    # ---------- 4. 最早的 5% 标签 ----------
    lines.append("\n## 4. The earliest 5% of the v4 training labels (C; seeds 0–2)\n")
    rows = [("random 5%: baseline 50 epochs", run_dirs("temporal", "_e50_cwinv_sqrt_frac0.05", range(3))),
            ("random 5%: v3.1 auxiliary 5 epochs", run_dirs("temporal", "_aux_e5_cwinv_sqrt_frac0.05", range(3))),
            ("earliest 5%: baseline 50 epochs", run_dirs("temporal", "_e50_cwinv_sqrt_fracearly0.05", range(3))),
            ("earliest 5%: v3.1 auxiliary 5 epochs", run_dirs("temporal", "_aux_e5_cwinv_sqrt_fracearly0.05", range(3))),
            ("all labels: baseline 25 epochs", run_dirs("temporal", "_e25_cwinv_sqrt", range(3)))]
    table(lines, df, rows, ["all", "non_derived"])
    if rows[3][1] and rows[2][1]:
        compare(lines, df, "earliest 5%: auxiliary − baseline", rows[3][1], rows[2][1], ["all", "non_derived"])
        compare(lines, df, "earliest 5% with auxiliary − all labels baseline 25 epochs", rows[3][1], rows[4][1], ["all", "non_derived"])
    # 最早 5% 的构成（与 train_encoder.py 的取法相同：训练部分按发布日期排序后取前 5%）
    tr = df[df["pub"] < CUTOFF].sort_values("pub")
    tr = tr.iloc[:-max(1, int(0.1 * len(tr)))]
    early = tr.sort_values("pub", kind="stable").head(int(round(len(tr) * 0.05)))
    top = lambda d: ", ".join(f"{s} {n / len(d):.1%}" for s, n in d["source"].value_counts().head(4).items())  # noqa: E731
    lines.append(f"\nEarliest 5%: {len(early):,} labels, published from {early['pub'].min():%Y-%m-%d} to {early['pub'].max():%Y-%m-%d}; sources: {top(early)}; "
                 f"label types: " + ", ".join(f"{k} {v / len(early):.1%}" for k, v in early["label_type"].value_counts().items()) + "."
                 f"\nAll training labels: {len(tr):,}, published from {tr['pub'].min():%Y-%m-%d} to {tr['pub'].max():%Y-%m-%d}; sources: {top(tr)}.")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
