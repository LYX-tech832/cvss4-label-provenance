"""Configuration selection on each split's own validation set (CPU, seconds).

Each LOSO split selects its configuration in the same search space on its own validation set (the latest 10% of its training part,
without the held-out CNA); selecting on the temporal split's validation set would use early labels of the held-out CNA.
For the model without the auxiliary task, the cap on training epochs (5 / 10 / 25, each with the best epoch chosen on the validation set)
is selected as a further hyperparameter (a fully trained baseline). The temporal split also selects on its own validation set.
Usage: python src/select_loso_config.py            -> prints the selection table and writes results/review_gpu/config_selection.md
       python src/select_loso_config.py --shell    -> prints one line "split|training arguments" per selected configuration,
                                                     used by scripts/run_review_gpu4.sh to run its 5 seeds
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
OUT = ROOT / "results" / "review_gpu" / "config_selection.md"
SPLITS = ["temporal", "loso:VulnCheck", "loso:GitHub_M", "loso:VulDB"]
# 运行名后缀 → train_encoder.py 参数（与时间划分上 W4 的搜索空间相同：λ ∈ {0.5, 1.0} × 类别加权 ∈ {无, inv_sqrt}，5 轮）
AUX = {"_aux_e5_cwinv_sqrt": "--aux_v31 --aux_lambda 0.5 --class_weight inv_sqrt --epochs 5",
       "_aux_e5": "--aux_v31 --aux_lambda 0.5 --class_weight none --epochs 5",
       "_aux_lam1_e5_cwinv_sqrt": "--aux_v31 --aux_lambda 1.0 --class_weight inv_sqrt --epochs 5",
       "_aux_lam1_e5": "--aux_v31 --aux_lambda 1.0 --class_weight none --epochs 5"}
# 无辅助：类别加权 ∈ {无, inv_sqrt} × 轮数上限 ∈ {5, 10}；时间划分另加 25 轮（与辅助模型 5 轮的优化步数相当）
NONE = {"_e5_cwinv_sqrt": "--class_weight inv_sqrt --epochs 5", "_e5": "--class_weight none --epochs 5",
        "_e10_cwinv_sqrt": "--class_weight inv_sqrt --epochs 10", "_e10": "--class_weight none --epochs 10"}
NONE_TEMPORAL_EXTRA = {"_e25_cwinv_sqrt": "--class_weight inv_sqrt --epochs 25"}
# 留一来源划分也加一个步数相当的候选，轮数 = 5 ×（v4 训练样本 + 6 万辅助样本）/ v4 训练样本
NONE_LOSO_EXTRA = {"loso:VulnCheck": {"_e16_cwinv_sqrt": "--class_weight inv_sqrt --epochs 16"},
                   "loso:GitHub_M": {"_e15_cwinv_sqrt": "--class_weight inv_sqrt --epochs 15"},
                   "loso:VulDB": {"_e18_cwinv_sqrt": "--class_weight inv_sqrt --epochs 18"}}


def val_f1(split, tag):
    f = ENC / f"T2_{split.replace(':', '-')}_deberta-v3-base_none{tag}_s0" / "results.json"
    return json.loads(f.read_text(encoding="utf-8"))["val_best_mean_f1"] if f.exists() else None


def select():
    out = {}
    for sp in SPLITS:
        cands = {"aux": AUX, "none": {**NONE, **(NONE_TEMPORAL_EXTRA if sp == "temporal" else NONE_LOSO_EXTRA[sp])}}
        out[sp] = {}
        for model, c in cands.items():
            scores = {tag: val_f1(sp, tag) for tag in c}
            done = {t: s for t, s in scores.items() if s is not None}
            best = max(done, key=done.get) if done else None
            out[sp][model] = {"scores": scores, "best": best, "args": c.get(best), "complete": len(done) == len(c)}
    return out


def main():
    sel = select()
    if "--shell" in sys.argv:
        for sp, d in sel.items():
            for model in ["aux", "none"]:
                if not d[model]["complete"]:
                    sys.exit(f"{sp} {model}: the search has not finished: {d[model]['scores']}")
                print(f"{sp}|{d[model]['args']}")
        return
    lines = ["# Configuration selected on each split's own validation set (seed 0, mean validation macro-F1; generated automatically)\n"]
    for sp, d in sel.items():
        for model in ["aux", "none"]:
            lines += [f"\n## {sp}, {'v3.1 auxiliary task' if model == 'aux' else 'baseline'}\n", "| Configuration | Mean validation macro-F1 | Selected |", "|---|---|---|"]
            for tag, s in d[model]["scores"].items():
                lines.append(f"| `{tag}` | {'—' if s is None else f'{s:.4f}'} | {'✓' if tag == d[model]['best'] else ''} |")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
