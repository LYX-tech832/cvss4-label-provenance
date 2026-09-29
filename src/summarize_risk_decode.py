"""汇总风险敏感解码（CPU）：读取各 W4 运行目录下的 risk_decode.json（src/risk_decode.py 生成），
按（划分, 版本）对种子取平均，比较 argmax 解码与"按验证集选定 α"的解码在测试集上的表现。
输出：results/encoder/risk_decode_summary.md
"""

import json
import re
from collections import defaultdict
from pathlib import Path

import numpy as np

ENC = Path(__file__).resolve().parents[1] / "results" / "encoder"
NAME = re.compile(r"^T2_(?P<split>.+?)_deberta-v3-base_none(?P<aux>_aux)?_e5_cwinv_sqrt_s(?P<seed>\d)$")
KEYS = ["mean_macro_f1", "band_acc", "under_rate", "hc_recall", "score_mae", "exact_match"]


def main():
    groups = defaultdict(list)
    for d in sorted(ENC.iterdir()):
        m = NAME.match(d.name)
        if m and (d / "risk_decode.json").exists():
            groups[(m["split"], "有辅助" if m["aux"] else "无辅助")].append(json.loads((d / "risk_decode.json").read_text(encoding="utf-8")))
    lines = ["# 风险敏感解码汇总（测试集；各种子取平均；α 只按验证集选：验证集宏 F1 比 argmax 下降不超过 0.01 时取低估率最低的 α）\n",
             "| 划分 | 版本 | 种子数 | 选定的 α | 解码 | " + " | ".join(KEYS) + " |", "|---|---|---|---|---|" + "---|" * len(KEYS)]
    for (split, ver), rs in sorted(groups.items()):
        alphas = "、".join(f"{r['chosen_alpha']:.1f}" for r in rs)
        for tag, key in [("argmax", "argmax"), ("选定 α", "chosen")]:
            vals = [np.mean([r[key][f"test_{k}"] for r in rs]) for k in KEYS]
            lines.append(f"| {split} | {ver} | {len(rs)} | {alphas if tag == 'argmax' else ''} | {tag} | " + " | ".join(f"{v:.3f}" for v in vals) + " |")
    out = ENC / "risk_decode_summary.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
