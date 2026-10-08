"""第二个编码器（10-07 用户同意做"中间那档"）：时间划分，有 / 无 v3.1 辅助任务，按验证集选配置后各跑 5 个种子。

子命令（都只读 results/encoder/ 下已有的运行，不需要 GPU）：
  select   按验证集的最佳平均宏 F1，从种子 0 的候选里为两个版本各选一个配置，与 DeBERTa 的做法相同：
           无辅助：类别加权 {无, inv_sqrt} × 轮数上限 {5, 10}，再加步数相当的 25 轮（类别加权）；
           有辅助：λ {0.5, 1} × 类别加权 {无, inv_sqrt}，5 轮。
           写 results/encoder/selected_config_<模型简称>.json；加 --shell 时只打印给脚本用的两行参数。
  summary  选中配置的各种子结果、均值和标准差，辅助任务的增益（配对 bootstrap 和逐种子差值），以及与 DeBERTa 的对照。
           写 results/review_gpu/summary6.md。
用法：python src/second_encoder.py select|summary [--model ehsanaghaei/SecureBERT] [--shell]
用 --model microsoft/deberta-v3-base 跑 select / summary 可以核对脚本：应选出 25 轮（0.6769）和 λ = 0.5 加权（0.6948），增益 +0.025 [+0.023, +0.026]。
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
OUT = ROOT / "results" / "review_gpu" / "summary6.md"
NONE_GRID = {(5, "none"), (5, "inv_sqrt"), (10, "none"), (10, "inv_sqrt"), (25, "inv_sqrt")}
PLAIN = {"aux_shuffle": False, "aux_cwe": False, "pseudo_v4": False, "v31_only": False, "no_cwe_in_text": False, "train_frac": 1.0,
         "exclude_ids": None, "init_encoder": None, "save_encoder": False, "frac_mode": "random"}


def runs(model):
    """该模型在时间划分上的"普通"运行：返回 [(版本, 配置, 种子, 目录)]；配置 = (轮数上限, 类别加权, λ)。"""
    out = []
    for d in sorted(ENC.iterdir()):
        f = d / "args.json"
        if not f.exists() or not (d / "results.json").exists():
            continue
        a = json.loads(f.read_text(encoding="utf-8"))
        if a.get("model") != model or a.get("task") != "T2" or a.get("split") != "temporal" or a.get("source_mode") != "none" or a.get("smoke_test"):
            continue
        if any(a.get(k, v) != v for k, v in PLAIN.items()):
            continue
        if a.get("aux_v31"):
            if a["epochs"] == 5 and a.get("aux_lambda") in (0.5, 1.0) and a.get("aux_max", 60000) == 60000:
                out.append(("aux", (5, a.get("class_weight", "none"), a["aux_lambda"]), a["seed"], d))
        elif (a["epochs"], a.get("class_weight", "none")) in NONE_GRID:
            out.append(("none", (a["epochs"], a.get("class_weight", "none"), None), a["seed"], d))
    return out


def val(d):
    r = json.loads((d / "results.json").read_text(encoding="utf-8"))
    return r["val_best_mean_f1"], r["best_epoch"]


def select(model, quiet=False):
    cand = {"none": {}, "aux": {}}
    for ver, cfg, seed, d in runs(model):
        if seed == 0:
            cand[ver][cfg] = (*val(d), d.name)
    chosen = {}
    for ver in ("none", "aux"):
        if not cand[ver]:
            continue
        best = max(cand[ver], key=lambda c: cand[ver][c][0])
        args = f"--epochs {best[0]} --class_weight {best[1]}" + (f" --aux_v31 --aux_lambda {best[2]:g}" if ver == "aux" else "")
        chosen[ver] = {"config": list(best), "val_best_mean_f1": cand[ver][best][0], "run": cand[ver][best][2], "args": args,
                       "candidates": {f"e{c[0]}_{c[1]}" + (f"_lam{c[2]:g}" if c[2] else ""): round(v[0], 4) for c, v in sorted(cand[ver].items())}}
        if not quiet:
            print(f"[{ver}] 候选（验证集最佳平均宏 F1）：")
            for c, v in sorted(cand[ver].items(), key=lambda x: -x[1][0]):
                print(f"   {v[0]:.4f}  最佳轮次 {v[1] + 1}  {v[2]}")
    return chosen


def summary(model):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from aggregate_seeds import Encoded, fast_scores, paired_bootstrap  # noqa: E402
    from baselines_v0 import CUTOFF, load, source_type_map  # noqa: E402

    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    t = Encoded(test, "y_")
    scopes = {"all": np.arange(len(test)), "non-derived": np.flatnonzero((test["label_type"] != "derived").to_numpy())}
    keys = ["mean_macro_f1", "band_acc", "under_rate", "score_mae"]
    lines = ["# 第二个编码器：v3.1 辅助任务的增益是否依赖编码器（时间划分，自动生成）\n"]
    gains, encs = {}, {}
    for m in [model, "microsoft/deberta-v3-base"]:
        ch = select(m, quiet=True)
        if set(ch) != {"none", "aux"}:
            lines.append(f"\n## {m}：候选配置没有跑全，跳过\n")
            continue
        allruns = runs(m)
        dirs = {ver: {s: d for v, c, s, d in allruns if v == ver and list(c) == ch[ver]["config"]} for ver in ("none", "aux")}
        lines += [f"\n## {m}\n", "验证集选中的配置（种子 0）：无辅助 " + ch["none"]["args"] + f"（{ch['none']['val_best_mean_f1']:.4f}）；有辅助 " + ch["aux"]["args"] + f"（{ch['aux']['val_best_mean_f1']:.4f}）。",
                  "候选的验证集得分：无辅助 " + json.dumps(ch["none"]["candidates"]) + "；有辅助 " + json.dumps(ch["aux"]["candidates"]) + "\n",
                  "| 版本 | 种子 | 范围 | 平均宏 F1（均值 ± 标准差） | 等级准确率 | 低估率 | MAE |", "|---|---|---|---|---|---|---|"]
        per = {}
        for ver in ("none", "aux"):
            es = encs[(m, ver)] = {s: Encoded(pd.read_parquet(d / "pred_latent.parquet").set_index("cve_id").loc[test["cve_id"]].reset_index()) for s, d in sorted(dirs[ver].items())}
            for sc, idx in scopes.items():
                rs = {s: fast_scores(t, e, idx) for s, e in es.items()}
                per[(ver, sc)] = rs
                f = [r["mean_macro_f1"] for r in rs.values()]
                lines.append(f"| {'无辅助' if ver == 'none' else '有 v3.1 辅助'} | {sorted(rs)} | {sc} | {np.mean(f):.3f} ± {np.std(f, ddof=1) if len(f) > 1 else float('nan'):.3f} | "
                             + " | ".join(f"{np.mean([r[k] for r in rs.values()]):.3f}" for k in keys[1:]) + " |")
        common = sorted(set(dirs["none"]) & set(dirs["aux"]))
        if len(common) < 2:
            lines.append("\n两个版本共同的种子不足 2 个，不算增益。")
            continue
        bs = paired_bootstrap(df, {s: dirs["none"][s] for s in common}, {s: dirs["aux"][s] for s in common})
        lines += [f"\n增益（有辅助 − 无辅助；种子 {common}；配对 bootstrap 1,000 次，95% 区间）：\n", "| 范围 | 平均宏 F1 | 等级准确率 | 低估率 | 逐种子的平均宏 F1 差 |", "|---|---|---|---|---|"]
        for sc, key in [("all", "all"), ("non-derived", "non_derived")]:
            b = bs[key]
            seedwise = ", ".join(f"{per[('aux', sc)][s]['mean_macro_f1'] - per[('none', sc)][s]['mean_macro_f1']:+.3f}" for s in common)
            lines.append(f"| {sc} | " + " | ".join(f"{b[k][0]:+.3f} [{b[k][1]:+.3f}, {b[k][2]:+.3f}]" for k in keys[:3]) + f" | {seedwise} |")
        gains[m] = bs["all"]["mean_macro_f1"][0]
    if len(gains) == 2:
        a, b = gains[model], gains["microsoft/deberta-v3-base"]
        lines.append(f"\n**对照**：平均宏 F1 的增益，{Path(model).name} {a:+.3f}，DeBERTa-v3-base {b:+.3f}。")
    pf = ROOT / "results" / "pipeline_baseline" / "predictions" / "T2_temporal_pipeline_rule_R.parquet"
    if pf.exists():
        # 与表 S33 相同的比较：直接预测 v4.0 的模型 − 不用 v4.0 标签的 TF-IDF 流水线（规则 R）
        pe = Encoded(pd.read_parquet(pf).set_index("cve_id").loc[test["cve_id"]].reset_index())
        rng = np.random.default_rng(0)

        def sc(es, ix):
            rs = [fast_scores(t, e, ix) for e in es]
            return np.array([np.mean([r[k] for r in rs]) for k in keys[:3]])
        lines += ["\n## 与 TF-IDF 流水线（规则 R，不用 v4.0 标签）的对照：模型 − 流水线（各种子平均；配对 bootstrap 1,000 次，95% 区间）\n",
                  "DeBERTa 两行用来核对：点估计应与论文表 S33 相同，区间因随机数序列不同可能差 0.001。\n",
                  "| 模型 | 范围 | 平均宏 F1 | 等级准确率 | 低估率 |", "|---|---|---|---|---|"]
        for (m, ver), es in encs.items():
            for sc_name, idx in scopes.items():
                d = sc(list(es.values()), idx) - sc([pe], idx)
                bs = np.array([sc(list(es.values()), ix) - sc([pe], ix) for ix in (rng.choice(idx, size=len(idx), replace=True) for _ in range(1000))])
                lines.append(f"| {Path(m).name} {'无辅助' if ver == 'none' else '有 v3.1 辅助'} | {sc_name} | "
                             + " | ".join(f"{d[j]:+.3f} [{np.percentile(bs[:, j], 2.5):+.3f}, {np.percentile(bs[:, j], 97.5):+.3f}]" for j in range(3)) + " |")
        # DeBERTa 流水线（只学 v3.1 头，再用规则 R 转换；种子 0–2，论文 6.2 节）：不用 v4.0 标签的模型里等级准确率最高的一个
        dp = [ENC / f"T2_temporal_deberta-v3-base_none_v31only_e5_s{s}" / "pred_latent.parquet" for s in range(3)]
        if all(f.exists() for f in dp):
            dpe = [Encoded(pd.read_parquet(f).set_index("cve_id").loc[test["cve_id"]].reset_index()) for f in dp]
            lines += ["\n## 与 DeBERTa 流水线（不用 v4.0 标签，种子 0–2 平均）的对照：有 v3.1 辅助的模型 − DeBERTa 流水线\n",
                      "流水线点估计（核对用，论文 7.2 节：平均宏 F1 0.601、低估率 0.111、非 derived 等级准确率 0.561）："
                      + "；".join(f"{n} 平均宏 F1 {sc(dpe, ix)[0]:.3f}、等级准确率 {sc(dpe, ix)[1]:.3f}、低估率 {sc(dpe, ix)[2]:.3f}" for n, ix in scopes.items()) + "。\n",
                      "| 模型 | 范围 | 平均宏 F1 | 等级准确率 | 低估率 |", "|---|---|---|---|---|"]
            for (m, ver), es in encs.items():
                if ver != "aux":
                    continue
                for sc_name, idx in scopes.items():
                    d = sc(list(es.values()), idx) - sc(dpe, idx)
                    bs = np.array([sc(list(es.values()), ix) - sc(dpe, ix) for ix in (rng.choice(idx, size=len(idx), replace=True) for _ in range(1000))])
                    lines.append(f"| {Path(m).name} 有 v3.1 辅助 | {sc_name} | "
                                 + " | ".join(f"{d[j]:+.3f} [{np.percentile(bs[:, j], 2.5):+.3f}, {np.percentile(bs[:, j], 97.5):+.3f}]" for j in range(3)) + " |")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\n已写入 {OUT}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["select", "summary"])
    ap.add_argument("--model", default="ehsanaghaei/SecureBERT")
    ap.add_argument("--shell", action="store_true", help="select：只打印 NONE_ARGS / AUX_ARGS 两行，供脚本 eval")
    a = ap.parse_args()
    if a.cmd == "summary":
        return summary(a.model)
    ch = select(a.model, quiet=a.shell)
    if set(ch) != {"none", "aux"}:
        print(f"候选没有跑全：{sorted(ch)}", file=sys.stderr)
        sys.exit(1)
    (ENC / f"selected_config_{Path(a.model).name}.json").write_text(json.dumps(ch, indent=1, ensure_ascii=False), encoding="utf-8")
    if a.shell:
        print(f'NONE_ARGS="{ch["none"]["args"]}"\nAUX_ARGS="{ch["aux"]["args"]}"')
    else:
        print("\n选定：\n  无辅助 " + ch["none"]["args"] + "\n  有辅助 " + ch["aux"]["args"])


if __name__ == "__main__":
    main()
