"""风险敏感解码（CPU，后处理）：在准确率与"低估严重性"之间取平衡。

规则：对每个指标，候选集 = 概率 ≥ α × 最大概率的类别；在候选集中选"最严重"的类别。
  α = 1 等价于普通的 argmax；α 越小，越倾向于往严重的方向判。
各指标的严重程度排序（从最严重到最轻，按 CVSS v4.0 规范的含义）：
  AV: N > A > L > P；AC: L > H；AT: N > P；PR: N > L > H；UI: N > P > A；
  VC/VI/VA/SC/SI/SA: H > L > N
α 的选择只用验证集：在"验证集平均 F1 比 argmax 下降不超过 --max_f1_drop"的 α 中，选验证集低估率最低的那个。
输入：results/encoder/<运行名>/probs.npz（train_encoder.py 保存）
输出：<运行目录>/risk_decode.json，并打印 α 扫描表
用法：python src/risk_decode.py results/encoder/<运行名> [更多运行目录...]
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
