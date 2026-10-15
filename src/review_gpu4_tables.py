"""Rows for the configurations selected on each split's own validation set: the DeBERTa rows of Table 2, the standard deviations
of Table S24, the risk-sensitive decoding rows of Table 3, and several differences quoted in the text (CPU, about 5 minutes).
Output: results/review_gpu/tables4.md
"""

import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import paired_bootstrap  # noqa: E402
from baselines_v0 import load, source_type_map  # noqa: E402
from review_gpu4_summary import COLS, SPLITS, describe, run_dirs, tag_of  # noqa: E402
from select_loso_config import select  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "review_gpu" / "tables4.md"
NAMES = {"temporal": "Temporal", "loso:VulnCheck": "LOSO–VulnCheck", "loso:GitHub_M": "LOSO–GitHub", "loso:VulDB": "LOSO–VulDB"}


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    sel = select()
    lines = ["# Rows of Tables 2, S24 and 3 (configurations selected on each split's own validation set; generated automatically)\n", "## Table 2: the two DeBERTa rows (mean) and Table S24 (standard deviation)\n"]
    for sp in SPLITS:
        ta, tn = tag_of(sel[sp]["aux"]["args"]), tag_of(sel[sp]["none"]["args"])
        for scope in (["all", "non_derived"] if sp == "temporal" else ["all"]):
            lines.append(f"\n### {NAMES[sp]}, {scope} (baseline `{tn}`, auxiliary `{ta}`)\n")
            for label, tag in [("DeBERTa", tn), ("DeBERTa + v3.1 aux.", ta)]:
                m = describe(run_dirs(sp, tag), df, scope)
                lines.append(f"mean | {label} | " + " | ".join(f"{m[k][0]:.3f}" for k, _ in COLS) + " |")
                lines.append(f"sd   | {label} | " + " | ".join(f"{m[k][1]:.3f}" for k, _ in COLS) + " |")
    lines.append("\n## Table 3: risk-sensitive decoding (selected configuration of the auxiliary-task model, mean over 5 seeds; Over = 1 − Band − Under, from unrounded values)\n")
    for sp in SPLITS:
        ta = tag_of(sel[sp]["aux"]["args"])
        rs = [json.loads((d / "risk_decode.json").read_text(encoding="utf-8")) for d in run_dirs(sp, ta).values()]
        for tagname, key in [("argmax", "argmax"), ("risk-sensitive", "chosen")]:
            v = {k: np.mean([r[key][f"test_{k}"] for r in rs]) for k in ["mean_macro_f1", "band_acc", "under_rate", "hc_recall", "score_mae"]}
            over = 1 - v["band_acc"] - v["under_rate"]
            lines.append(f"| {NAMES[sp]} | {tagname} | {v['mean_macro_f1']:.3f} | {v['band_acc']:.3f} | {v['under_rate']:.3f} | {over:.3f} | {v['hc_recall']:.3f} | {v['score_mae']:.3f} |")
        lines.append(f"(α: {', '.join(str(r['chosen_alpha']) for r in rs)})")
    lines.append("\n## Quoted in the text: temporal split, auxiliary 5 epochs − baseline 25 epochs, differences in underestimation rate and MAE (paired bootstrap)\n")
    b = paired_bootstrap(df, run_dirs("temporal", "_e25_cwinv_sqrt"), run_dirs("temporal", "_aux_e5_cwinv_sqrt"))
    for scope in ["all", "non_derived"]:
        lines.append(f"- {scope}: " + "; ".join(f"{k} {b[scope][k][0]:+.3f} [{b[scope][k][1]:+.3f}, {b[scope][k][2]:+.3f}]" for k in ["mean_macro_f1", "band_acc", "under_rate", "score_mae"]))
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
