"""Selects one configuration each for the baseline and the auxiliary variant from the W4 tuning results (best mean validation F1 only).
Reads val_best_mean_f1 from results/encoder/T2_temporal_deberta-v3-base_none*_e5*_s0/results.json.
Output: the arguments for run_w4_seeds.sh (NONE_ARGS / AUX_ARGS), also written to results/encoder/selected_config.json
"""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
NAME = re.compile(r"^T2_temporal_deberta-v3-base_none(?P<aux>_aux)?(?:_lam(?P<lam>[0-9.]+))?_e5(?:_cw(?P<cw>\w+?))?_s0$")


def main():
    cands = {"none": [], "aux": []}
    for d in ENC.iterdir():
        m = NAME.match(d.name)
        f = d / "results.json"
        if not m or not f.exists():
            continue
        r = json.loads(f.read_text(encoding="utf-8"))
        ver = "aux" if m["aux"] else "none"
        args = ["--epochs", "5", "--class_weight", m["cw"] or "none"]
        if ver == "aux":
            args += ["--aux_v31", "--aux_lambda", m["lam"] or "0.5"]
        cands[ver].append((r["val_best_mean_f1"], r["best_epoch"], d.name, args))
    chosen = {}
    for ver, lst in cands.items():
        print(f"\n[{ver}] 候选（验证集最佳平均 F1，最佳轮次，运行名）：")
        for f1, ep, name, _ in sorted(lst, reverse=True):
            print(f"  {f1:.4f}  epoch {ep}  {name}")
        if lst:
            best = max(lst)
            chosen[ver] = {"val_best_mean_f1": best[0], "run": best[2], "args": " ".join(best[3])}
    (ENC / "selected_config.json").write_text(json.dumps(chosen, indent=1, ensure_ascii=False), encoding="utf-8")
    print("\n选定配置：")
    for ver, c in chosen.items():
        print(f'  {"NONE_ARGS" if ver == "none" else "AUX_ARGS"}="{c["args"]}"   （验证集 {c["val_best_mean_f1"]:.4f}）')


if __name__ == "__main__":
    main()
