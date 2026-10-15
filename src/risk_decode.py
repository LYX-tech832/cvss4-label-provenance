"""Risk-sensitive decoding (CPU, post-processing): a balance between accuracy and underestimating severity.

Rule: for each metric, the candidate set is the classes with probability >= α × the maximum probability; the most severe class in the
candidate set is chosen. α = 1 equals ordinary argmax; the smaller α, the more the decision leans towards severe values.
Severity order of each metric (most to least severe, following the meaning in the CVSS v4.0 specification):
  AV: N > A > L > P; AC: L > H; AT: N > P; PR: N > L > H; UI: N > P > A;
  VC/VI/VA/SC/SI/SA: H > L > N
α is selected on the validation set only: among the α that lower the mean validation F1 by at most --max_f1_drop relative to argmax,
the one with the lowest validation underestimation rate.
Input: results/encoder/<run name>/probs.npz (saved by train_encoder.py)
Output: <run directory>/risk_decode.json; the scan over α is printed
Usage: python src/risk_decode.py results/encoder/<run name> [more run directories...]
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import M40, evaluate, load  # noqa: E402
from cvss_utils import V40_METRICS  # noqa: E402

SEVERITY = {"AV": ["N", "A", "L", "P"], "AC": ["L", "H"], "AT": ["N", "P"], "PR": ["N", "L", "H"], "UI": ["N", "P", "A"],
            **{k: ["H", "L", "N"] for k in ["VC", "VI", "VA", "SC", "SI", "SA"]}}
ALPHAS = [1.0, 0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3]
KEYS = ["mean_macro_f1", "exact_match", "band_acc", "under_rate", "hc_recall", "score_mae"]


def decode(probs, alpha):
    out = {}
    for k in M40:
        p = probs[k].astype(np.float32)
        ok = p >= alpha * p.max(1, keepdims=True)
        labels = V40_METRICS[k]
        choice = np.full(len(p), -1)
        for c in reversed(SEVERITY[k]):  # 从最轻到最严重依次覆盖，最后留下的是候选集中最严重的类别
            idx = labels.index(c)
            choice = np.where(ok[:, idx], idx, choice)
        out[k] = np.array(labels)[choice]
    return pd.DataFrame(out)


def truth(df, ids):
    t = df.set_index("cve_id").loc[ids].reset_index()
    return t


def run(run_dir, df, max_f1_drop):
    z = np.load(Path(run_dir) / "probs.npz")
    sets = {}
    for part in ["val", "test"]:
        ids = z[f"{part}_cve_id"]
        sets[part] = (truth(df, ids), {k: z[f"{part}_{k}"] for k in M40})
    scan = []
    for a in ALPHAS:
        row = {"alpha": a}
        for part, (t, p) in sets.items():
            r = evaluate(t, decode(p, a))
            row |= {f"{part}_{k}": r[k] for k in KEYS}
        scan.append(row)
    base_f1 = scan[0]["val_mean_macro_f1"]
    ok = [r for r in scan if r["val_mean_macro_f1"] >= base_f1 - max_f1_drop]
    chosen = min(ok, key=lambda r: (r["val_under_rate"], -r["val_mean_macro_f1"]))
    res = {"max_f1_drop": max_f1_drop, "chosen_alpha": chosen["alpha"], "argmax": scan[0], "chosen": chosen, "scan": scan}
    (Path(run_dir) / "risk_decode.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dirs", nargs="+")
    ap.add_argument("--max_f1_drop", type=float, default=0.01, help="允许验证集平均 F1 比 argmax 最多下降多少")
    args = ap.parse_args()
    df = load()
    for d in args.run_dirs:
        res = run(d, df, args.max_f1_drop)
        print(f"\n== {Path(d).name}  → 选定 α = {res['chosen_alpha']}（依据验证集）")
        print("α    | 验证: 平均F1 等级准确率 低估率 | 测试: 平均F1 全对 等级准确率 低估率 HC召回")
        for r in res["scan"]:
            mark = " ←" if r["alpha"] == res["chosen_alpha"] else ""
            print(f"{r['alpha']:.1f}  | {r['val_mean_macro_f1']:.3f} {r['val_band_acc']:.3f} {r['val_under_rate']:.3f} | "
                  f"{r['test_mean_macro_f1']:.3f} {r['test_exact_match']:.3f} {r['test_band_acc']:.3f} {r['test_under_rate']:.3f} {r['test_hc_recall']:.3f}{mark}")


if __name__ == "__main__":
    main()
