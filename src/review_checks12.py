"""补充的一项核对（10-09；CPU，约 3 分钟；只读已有的预测）。

论文 7.3 节写"On the R-inconsistent subset, the 5% model trails ... by 0.017"，这个数原来只有点估计、没有出处。
这里按论文其他差值的算法补上区间：随机 5% v4.0 训练标签 + v3.1 辅助（种子 0–2）对 全部标签、无辅助、25 轮（表 7 选中的基线，同样取种子 0–2），
时间划分测试集，子集为全部、非 derived、R-inconsistent；配对 bootstrap（测试 CVE 重抽样 1,000 次，各版本种子平均）。
输出：results/review_checks/summary18.md
"""

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded  # noqa: E402
from baselines_v0 import CUTOFF, evaluate, load, source_type_map  # noqa: E402
from review_checks import clean_mask  # noqa: E402
from review_gpu2_summary import boot, read, runs  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "review_checks" / "summary18.md"


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    stem = "T2_temporal_deberta-v3-base_none"
    vers = {"5% + v3.1 辅助": runs(stem, "_aux_e5_cwinv_sqrt_frac0.05", range(3)),
            "全部标签，无辅助 25 轮": runs(stem, "_e25_cwinv_sqrt", range(3))}
    assert all(len(p) == 3 for p in vers.values()), {k: len(v) for k, v in vers.items()}
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    test["clean"] = clean_mask(test)
    ids = test["cve_id"]
    t = Encoded(test, "y_")
    preds = {v: read(p, ids) for v, p in vers.items()}
    enc = {v: [Encoded(p) for p in ps] for v, ps in preds.items()}
    lines = ["# 5% 标签 + v3.1 辅助 对 全部标签、无辅助、25 轮（时间划分，种子 0–2；自动生成）\n"]
    subsets = {"全部": np.ones(len(test), bool), "非 derived": (test["label_type"] != "derived").to_numpy(),
               "R-inconsistent": test["clean"].to_numpy()}
    for name, m in subsets.items():
        idx = np.flatnonzero(m)
        tt = test.iloc[idx].reset_index(drop=True)
        lines += [f"\n## {name}：n = {len(idx):,}\n", "| 版本 | 种子数 | 平均宏 F1（均值 ± 标准差） | 等级准确率 |", "|---|---|---|---|"]
        for v, ps in preds.items():
            rs = [evaluate(tt, p.iloc[idx].reset_index(drop=True)) for p in ps]
            mf = [r["mean_macro_f1"] for r in rs]
            lines.append(f"| {v} | {len(ps)} | {np.mean(mf):.3f} ± {np.std(mf, ddof=1):.3f} | {np.mean([r['band_acc'] for r in rs]):.3f} |")
        rng = np.random.default_rng(0)
        k, c0, c1 = boot(t, enc, "5% + v3.1 辅助", "全部标签，无辅助 25 轮", idx, rng)
        lines += ["\n| A − B | 共同种子数 | 平均宏 F1 差 | 等级准确率差 |", "|---|---|---|---|",
                  f"| 5% + v3.1 辅助 − 全部标签，无辅助 25 轮 | {k} | {c0} | {c1} |"]
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
