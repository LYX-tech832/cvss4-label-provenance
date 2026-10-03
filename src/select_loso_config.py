"""第二轮审稿 P1/P4（10-02）：每个划分只用自己的验证集选配置（CPU，几秒）。

原做法：配置在时间划分的验证集上选（种子 0），再用于所有划分；时间划分的验证集含被留出 CNA 的早期标签（泄漏）。
新做法：每个 LOSO 划分用它自己的验证集（训练部分最晚的 10%，不含被留出的 CNA）在同样的搜索空间里选；
无辅助模型的训练轮数上限（5 / 10 / 25 轮，各自按验证集选最佳轮次）也作为超参数一起选（P4：充分训练的基线）。
时间划分同样按自己的验证集选（与原来一致，只是无辅助模型多了轮数上限这一维）。
用法：python src/select_loso_config.py            → 打印选择表，写 results/review_gpu/config_selection.md
      python src/select_loso_config.py --shell    → 每行输出 "划分|训练参数"，供 scripts/run_review_gpu4.sh 跑选中配置的 5 个种子
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
OUT = ROOT / "results" / "review_gpu" / "config_selection.md"
SPLITS = ["temporal", "loso:VulnCheck", "loso:GitHub_M", "loso:VulDB"]
# 运行名后缀 → train_encoder.py 参数（与时间划分上原来的搜索空间相同：λ ∈ {0.5, 1.0} × 类别加权 ∈ {无, inv_sqrt}，5 轮）
AUX = {"_aux_e5_cwinv_sqrt": "--aux_v31 --aux_lambda 0.5 --class_weight inv_sqrt --epochs 5",
       "_aux_e5": "--aux_v31 --aux_lambda 0.5 --class_weight none --epochs 5",
       "_aux_lam1_e5_cwinv_sqrt": "--aux_v31 --aux_lambda 1.0 --class_weight inv_sqrt --epochs 5",
       "_aux_lam1_e5": "--aux_v31 --aux_lambda 1.0 --class_weight none --epochs 5"}
# 无辅助：类别加权 ∈ {无, inv_sqrt} × 轮数上限 ∈ {5, 10}；时间划分另加 25 轮（与辅助模型 5 轮的优化步数相当）
NONE = {"_e5_cwinv_sqrt": "--class_weight inv_sqrt --epochs 5", "_e5": "--class_weight none --epochs 5",
        "_e10_cwinv_sqrt": "--class_weight inv_sqrt --epochs 10", "_e10": "--class_weight none --epochs 10"}
NONE_TEMPORAL_EXTRA = {"_e25_cwinv_sqrt": "--class_weight inv_sqrt --epochs 25"}


def val_f1(split, tag):
    f = ENC / f"T2_{split.replace(':', '-')}_deberta-v3-base_none{tag}_s0" / "results.json"
    return json.loads(f.read_text(encoding="utf-8"))["val_best_mean_f1"] if f.exists() else None


def select():
    out = {}
    for sp in SPLITS:
        cands = {"aux": AUX, "none": {**NONE, **(NONE_TEMPORAL_EXTRA if sp == "temporal" else {})}}
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
                    sys.exit(f"{sp} {model} 的搜索还没跑完：{d[model]['scores']}")
                print(f"{sp}|{d[model]['args']}")
        return
    lines = ["# 每个划分按自己的验证集选配置（种子 0，验证集平均宏 F1；自动生成）\n"]
    for sp, d in sel.items():
        for model in ["aux", "none"]:
            lines += [f"\n## {sp}，{'v3.1 辅助' if model == 'aux' else '无辅助'}\n", "| 配置 | 验证集平均宏 F1 | 选中 |", "|---|---|---|"]
            for tag, s in d[model]["scores"].items():
                lines.append(f"| `{tag}` | {'—' if s is None else f'{s:.4f}'} | {'✓' if tag == d[model]['best'] else ''} |")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
