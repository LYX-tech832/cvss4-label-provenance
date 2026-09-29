"""CWE 辅助任务对照实验的汇总（CPU）：v3.1 辅助任务的增益，是否只因为辅助模型多看了约 6 万条 CVE 描述、多了一个监督信号（第 8.2 节）。

三组运行（scripts/run_cwe_control.sh；T2 时间划分；W4 选定配置：5 轮、inv_sqrt 类别加权、λ = 0.5；种子 0–2），输入都只用描述
（--no_cwe_in_text。CWE 编号若在输入里，预测 CWE 类别就等于照抄输入，对照失去意义）：
  none_desc   无辅助；
  v31_desc    v3.1 辅助（与 W4 相同，只是输入去掉 CWE 编号）；
  cwe_desc    CWE 辅助：同一批辅助样本（同一个池、同一个种子），监督信号换成其第一个 CWE（前 50 个 + 其他，共 51 类）。
参照：W4 的无辅助 / v3.1 辅助（输入含 CWE 编号），种子 0–2 与上面配对；逐指标一节另列种子 0–4（即第 7.3 节的数字）。
输出只作描述，不下结论（判读规则事先写在 HANDOFF.md）：
  - 各组均值 ± 标准差（全部测试集 / 去掉 derived）；各运行的最佳轮次；
  - 配对 bootstrap（aggregate_seeds.paired_bootstrap，1,000 次，先按种子平均，95% 百分位区间）；
  - 逐指标宏 F1 的差值：有 v3.1 对应项的 7 个指标与没有的 4 个（AT、SC、SI、SA）分别平均（第 7.3 节口径）；
  - CWE 监督的覆盖率（各 CWE 辅助运行的 cwe_vocab.json）。
用法：python src/cwe_control.py [--enc 运行目录所在文件夹] [--out 输出文件夹] [--boot 1000]
输出：results/cwe_control/summary.md
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import BOOT_KEYS, paired_bootstrap  # noqa: E402
from baselines_v0 import M40, evaluate, load, source_type_map  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
STEM = "T2_temporal_deberta-v3-base_none"
GROUPS = {"none_desc": "_desconly", "v31_desc": "_aux_desconly", "cwe_desc": "_auxcwe_desconly", "none_w4": "", "v31_w4": "_aux"}
LABELS = {"none_desc": "无辅助（只用描述）", "v31_desc": "v3.1 辅助（只用描述）", "cwe_desc": "CWE 辅助（只用描述）",
          "none_w4": "无辅助（W4，描述 + CWE）", "v31_w4": "v3.1 辅助（W4，描述 + CWE）"}
SHORT = {"none_desc": "none", "v31_desc": "v31", "cwe_desc": "CWE", "none_w4": "none(W4)", "v31_w4": "v31(W4)"}
SEEDS = [0, 1, 2]
CONTRASTS = [("v31_desc", "none_desc"), ("cwe_desc", "none_desc"), ("v31_desc", "cwe_desc"), ("v31_w4", "none_w4")]
NEW4 = ["AT", "SC", "SI", "SA"]  # v4.0 新增或重构、没有直接 v3.1 对应项的指标（第 7.3 节）
SHARED = [k for k in M40 if k not in NEW4]
V4S = ["AT", "UI", "SC", "SI", "SA"]  # v4-specific F1 的口径（第 5 节）
KEYS = [("mean_macro_f1", "macro-F1"), ("v4_specific_f1", "v4-F1"), ("exact_match", "exact"), ("score_mae", "MAE"),
        ("band_acc", "band"), ("under_rate", "under"), ("hc_recall", "H+C rec.")]
SCOPES = [("all", "全部测试集"), ("non_derived", "去掉 derived")]


def run_dirs(enc, group, seeds=SEEDS):
    """返回 {种子: 运行目录}（只收有预测文件的）。"""
    out = {}
    for s in seeds:
        d = enc / f"{STEM}{GROUPS[group]}_e5_cwinv_sqrt_s{s}"
        if (d / "pred_latent.parquet").exists():
            out[s] = d
    return out


def scores(df, d):
    """一次运行在两种口径下的各项指标，以及 11 个指标各自的宏 F1（键名 f1_AV 等）。"""
    p = pd.read_parquet(d / "pred_latent.parquet")
    t = df.set_index("cve_id").loc[p["cve_id"]].reset_index()
    out = {}
    for scope, m in [("all", np.ones(len(t), bool)), ("non_derived", (t["label_type"] != "derived").to_numpy())]:
        r = evaluate(t[m].reset_index(drop=True), p[m].reset_index(drop=True))
        pm = {k: r["per_metric"][k]["macro_f1"] for k in M40}
        out[scope] = {k: r[k] for k, _ in KEYS if k in r} | {"v4_specific_f1": float(np.mean([pm[k] for k in V4S]))} \
            | {"f1_" + k: v for k, v in pm.items()}
    return out


def per_metric_delta(ra, rb, scope):
    """逐指标宏 F1 的差值（A − B，各自先按种子平均）。"""
    avg = lambda rs, k: np.mean([r[scope]["f1_" + k] for r in rs.values()])  # noqa: E731
    return {k: avg(ra, k) - avg(rb, k) for k in M40}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--enc", default=str(ROOT / "results" / "encoder"), help="运行目录所在的文件夹")
    ap.add_argument("--out", default=str(ROOT / "results" / "cwe_control"), help="输出文件夹")
    ap.add_argument("--boot", type=int, default=1000, help="配对 bootstrap 的重抽样次数（0 = 不做）")
    args = ap.parse_args()
    enc, out = Path(args.enc), Path(args.out)
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")

    dirs = {g: run_dirs(enc, g) for g in GROUPS}
    dirs5 = {g: run_dirs(enc, g, range(5)) for g in ["none_w4", "v31_w4"]}
    res = {g: {s: scores(df, d) for s, d in ds.items()} for g, ds in dirs.items()}
    res5 = {g: {s: res[g][s] if s in res[g] else scores(df, d) for s, d in ds.items()} for g, ds in dirs5.items()}
    missing = [f"{g} 种子 {s}" for g in GROUPS for s in SEEDS if s not in dirs[g]]

    lines = ["# CWE 辅助任务对照实验（T2 时间划分，自动生成）\n",
             "前三组只用描述作输入（去掉 CWE 编号）；W4 两组（描述 + CWE 编号）作参照。配置：5 轮、inv_sqrt 类别加权、λ = 0.5；种子 0–2。\n"]
    if missing:
        lines.append(f"**缺少的运行**：{'、'.join(missing)}\n")

    # 1. 各组均值 ± 标准差
    for scope, name in SCOPES:
        lines += [f"\n## 各组均值 ± 标准差（{name}）\n",
                  "| 组 | 种子数 | " + " | ".join(c for _, c in KEYS) + " |", "|---|---|" + "---|" * len(KEYS)]
        for g, rs in res.items():
            if rs:
                vals = [[r[scope][k] for r in rs.values()] for k, _ in KEYS]
                lines.append(f"| {LABELS[g]} | {len(rs)} | " + " | ".join(
                    f"{np.mean(v):.3f} ± {np.std(v, ddof=1) if len(v) > 1 else 0:.3f}" for v in vals) + " |")

    # 2. 配对 bootstrap（paired_bootstrap 计算"第三个参数 − 第二个参数"）
    lines += [f"\n## 配对 bootstrap（A − B；先按种子平均；{args.boot:,} 次重抽样；95% 百分位区间）\n",
              "| A − B | 口径 | n | 种子数（A/B） | 平均宏 F1 差 | 等级准确率差 | 低估率差 | 分数 MAE 差 |", "|---|---|---|---|---|---|---|---|"]
    for a, b in CONTRASTS:
        if dirs[a] and dirs[b] and args.boot > 0:
            for scope, x in paired_bootstrap(df, dirs[b], dirs[a], B=args.boot).items():
                cells = " | ".join(f"{x[k][0]:+.3f} [{x[k][1]:+.3f}, {x[k][2]:+.3f}]" for k in BOOT_KEYS)
                lines.append(f"| {SHORT[a]} − {SHORT[b]} | {dict(SCOPES)[scope]} | {x['n']:,} | {len(dirs[a])}/{len(dirs[b])} | {cells} |")
    lines.append("\n组名：none = 无辅助，v31 = v3.1 辅助，CWE = CWE 辅助（均只用描述）；(W4) = 输入含 CWE 编号。"
                 "低估率和 MAE 越小越好，这两列的差值为负才表示改进。")

    # 3. 逐指标宏 F1 的差值
    cols = [(f"{SHORT[a]} − {SHORT[b]}", res[a], res[b]) for a, b in CONTRASTS if res[a] and res[b]]
    if res5["v31_w4"] and res5["none_w4"]:
        cols.append((f"v31(W4) − none(W4)，种子 0–{max(res5['v31_w4'])}", res5["v31_w4"], res5["none_w4"]))
    for scope, name in SCOPES:
        if not cols:
            break
        deltas = [per_metric_delta(ra, rb, scope) for _, ra, rb in cols]
        lines += [f"\n## 逐指标宏 F1 的差值（{name}；各组先按种子平均）\n",
                  "| 指标 | " + " | ".join(c for c, _, _ in cols) + " |", "|---|" + "---|" * len(cols)]
        lines += [f"| {k} | " + " | ".join(f"{d[k]:+.3f}" for d in deltas) + " |" for k in M40]
        for label, ks in [(f"有 v3.1 对应项的 {len(SHARED)} 个指标平均", SHARED), (f"{'/'.join(NEW4)} 平均", NEW4), ("11 个指标平均", M40)]:
            lines.append(f"| **{label}** | " + " | ".join(f"{np.mean([d[k] for k in ks]):+.3f}" for d in deltas) + " |")

    # 4. 各运行的最佳轮次（判断是否欠训练）与 CWE 监督的覆盖率
    lines += ["\n## 各运行的最佳轮次（按验证集平均宏 F1 选；轮次从 0 计，共 5 轮）\n", "| 组 | 种子 | 最佳轮次 | 验证集平均宏 F1 |", "|---|---|---|---|"]
    for g in GROUPS:
        for s, d in dirs[g].items():
            r = json.loads((d / "results.json").read_text(encoding="utf-8"))
            lines.append(f"| {LABELS[g]} | {s} | {r['best_epoch']} | {r['val_best_mean_f1']:.3f} |")
    infos = {s: json.loads((d / "cwe_vocab.json").read_text(encoding="utf-8")) for s, d in dirs["cwe_desc"].items() if (d / "cwe_vocab.json").exists()}
    if infos:
        lines += ["\n## CWE 监督的覆盖率（CWE 辅助运行；类别表只用训练部分建立）\n",
                  "| 种子 | v4 训练样本 | 辅助样本 | v4 样本有 CWE | 辅助样本有 CWE | 有 CWE 的样本中归入'其他' | 前 5 个 CWE |", "|---|---|---|---|---|---|---|"]
        for s, i in infos.items():
            lines.append(f"| {s} | {i['n_v4_rows']:,} | {i['n_aux_rows']:,} | {i['cwe_coverage_v4']:.1%} | {i['cwe_coverage_aux']:.1%} | "
                         f"{i['share_other']:.1%} | {', '.join(i['vocab'][:5])} |")

    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
