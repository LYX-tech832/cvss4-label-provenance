"""补充的一项核对（10-12；CPU，几分钟；只读已保存的预测）。

论文 7.2 节写"The gain is as large on labels that rule R cannot explain: +0.023 [+0.018, +0.027] on the
R-inconsistent subset and +0.027 [+0.024, +0.029] on the 8,823 test labels without a v3.1 vector from the same source"。
这两个差值是辅助任务模型（5 轮，五个种子）减去表 7 选中的基线编码器（25 轮，五个种子），
但 results/ 下的各份汇总只有对 5 轮、10 轮基线的差值，没有这一组的区间。这里重算一遍。
时间划分测试集；配对 bootstrap（测试 CVE 重抽样 1,000 次，各版本种子平均），做法与 review_gpu2_summary.py 相同。
输出：results/review_checks/summary20.md
"""

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded  # noqa: E402
from baselines_v0 import CUTOFF, load, source_type_map  # noqa: E402
from review_checks import clean_mask  # noqa: E402
from review_gpu2_summary import boot, read, runs  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "review_checks" / "summary20.md"


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    test["clean"] = clean_mask(test)
    stem = "T2_temporal_deberta-v3-base_none"
    vers = {"aux5": "_aux_e5_cwinv_sqrt", "none25": "_e25_cwinv_sqrt"}
    t = Encoded(test, "y_")
    enc = {v: [Encoded(p) for p in read(runs(stem, tag, range(5)), test["cve_id"])] for v, tag in vers.items()}
    subsets = {"全部": np.ones(len(test), bool), "非 derived": (test["label_type"] != "derived").to_numpy(),
               "R-inconsistent": test["clean"].to_numpy(), "无同来源 v3.1": (~test["has_v31"]).to_numpy()}
    lines = ["# 辅助任务模型（5 轮）− 基线编码器（25 轮，表 7 选中），按子集（自动生成）\n",
             f"种子数：辅助 {len(enc['aux5'])}，基线 {len(enc['none25'])}。配对 bootstrap，测试 CVE 重抽样 1,000 次。\n",
             "| 子集 | n | 平均宏 F1 差 | 等级准确率差 |", "|---|---|---|---|"]
    for name, m in subsets.items():
        idx = np.flatnonzero(m)
        k, f1, band = boot(t, enc, "aux5", "none25", idx, np.random.default_rng(0))
        lines.append(f"| {name} | {len(idx):,} | {f1} | {band} |")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
