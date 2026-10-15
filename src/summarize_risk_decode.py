"""Summary of risk-sensitive decoding (CPU): reads risk_decode.json in each W4 run directory (written by src/risk_decode.py),
averages over seeds per (split, variant), and compares argmax decoding with decoding at the α selected on the validation set, on the test set.
Output: results/encoder/risk_decode_summary.md
"""

import json
import re
from collections import defaultdict
from pathlib import Path

import numpy as np

ENC = Path(__file__).resolve().parents[1] / "results" / "encoder"
# LOSO 划分按各自验证集选中 λ = 1（_lam1），一并汇总
NAME = re.compile(r"^T2_(?P<split>.+?)_deberta-v3-base_none(?P<aux>_aux)?(?P<lam>_lam1)?_e5_cwinv_sqrt_s(?P<seed>\d)$")
KEYS = ["mean_macro_f1", "band_acc", "under_rate", "hc_recall", "score_mae", "exact_match"]


def main():
    groups = defaultdict(list)
    for d in sorted(ENC.iterdir()):
        m = NAME.match(d.name)
        if m and (d / "risk_decode.json").exists():
            groups[(m["split"], ("with aux, λ=1" if m["lam"] else "with aux") if m["aux"] else "baseline")].append(json.loads((d / "risk_decode.json").read_text(encoding="utf-8")))
    lines = ["# Risk-sensitive decoding (test set; mean over seeds; α selected on the validation set only: the α with the lowest underestimation rate among those that lower validation macro-F1 by at most 0.01 relative to argmax)\n",
             "| Split | Variant | Seeds | Selected α | Decoding | " + " | ".join(KEYS) + " |", "|---|---|---|---|---|" + "---|" * len(KEYS)]
    for (split, ver), rs in sorted(groups.items()):
        alphas = ", ".join(f"{r['chosen_alpha']:.1f}" for r in rs)
        for tag, key in [("argmax", "argmax"), ("selected α", "chosen")]:
            vals = [np.mean([r[key][f"test_{k}"] for r in rs]) for k in KEYS]
            lines.append(f"| {split} | {ver} | {len(rs)} | {alphas if tag == 'argmax' else ''} | {tag} | " + " | ".join(f"{v:.3f}" for v in vals) + " |")
    out = ENC / "risk_decode_summary.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
