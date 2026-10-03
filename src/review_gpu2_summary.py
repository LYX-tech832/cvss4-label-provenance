"""第六份审稿意见（SCI审稿报告.md）M5 的 GPU 实验汇总（CPU，几分钟）：

1. 打乱 v3.1 标签的负对照（时间划分，--aux_shuffle，种子 0–2）：与无辅助（5 轮、10 轮）、正常 v3.1 辅助、CWE 辅助、伪标签比较，
   子集为全部、非 derived、R-inconsistent（双版本评分且 v4.0 ≠ 规则 R(同来源 v3.1)）、无同来源 v3.1；另报 AT:Present 被预测为 None 的比例。
2. 三个 LOSO 划分的无辅助基线训练 10 轮（种子 0–4，已跑完多少用多少）：与无辅助 5 轮、辅助 5 轮比较。
差值为配对 bootstrap（测试 CVE 重抽样 1,000 次，各版本种子平均；种子数不同时只用共同的种子）。
输出：results/review_gpu/summary2.md
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded, fast_scores  # noqa: E402
from baselines_v0 import CUTOFF, evaluate, load, source_type_map  # noqa: E402
from review_checks import clean_mask  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
OUT = ROOT / "results" / "review_gpu" / "summary2.md"
SHARED = ["AV", "AC", "PR", "UI", "VC", "VI", "VA"]
NEW = ["AT", "SC", "SI", "SA"]


def runs(stem, tag, seeds):
    return [ENC / f"{stem}{tag}_s{s}" for s in seeds if (ENC / f"{stem}{tag}_s{s}" / "pred_latent.parquet").exists()]


def read(paths, ids):
    return [pd.read_parquet(p / "pred_latent.parquet").set_index("cve_id").loc[ids].reset_index() for p in paths]


def boot(t, enc, a, b, idx, rng, B=1000):
    k = min(len(enc[a]), len(enc[b]))

    def d(ix):
        fa = [fast_scores(t, e, ix) for e in enc[a][:k]]
        fb = [fast_scores(t, e, ix) for e in enc[b][:k]]
        return (np.mean([x["mean_macro_f1"] for x in fa]) - np.mean([x["mean_macro_f1"] for x in fb]),
                np.mean([x["band_acc"] for x in fa]) - np.mean([x["band_acc"] for x in fb]))
    pt = d(idx)
    bs = np.array([d(rng.choice(idx, size=len(idx), replace=True)) for _ in range(B)])
    ci = lambda j: f"{pt[j]:+.3f} [{np.percentile(bs[:, j], 2.5):+.3f}, {np.percentile(bs[:, j], 97.5):+.3f}]"  # noqa: E731
    return k, ci(0), ci(1)


def part1(df, lines):
    stem = "T2_temporal_deberta-v3-base_none"
    vers = {"无辅助 5 轮": ("_e5_cwinv_sqrt", range(5)), "无辅助 10 轮": ("_e10_cwinv_sqrt", range(3)),
            "打乱 v3.1 辅助 5 轮": ("_auxshuf_e5_cwinv_sqrt", range(3)), "v3.1 辅助 5 轮": ("_aux_e5_cwinv_sqrt", range(5)),
            "v3.1 辅助 10 轮": ("_aux_e10_cwinv_sqrt", range(3)), "CWE 辅助 5 轮": ("_auxcwe_desconly_e5_cwinv_sqrt", range(3)),
            "伪标签 5 轮": ("_pseudo_e5_cwinv_sqrt", range(3))}
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    test["clean"] = clean_mask(test)
    ids = test["cve_id"]
    t = Encoded(test, "y_")
    preds = {v: read(runs(stem, tag, seeds), ids) for v, (tag, seeds) in vers.items()}
    enc = {v: [Encoded(p) for p in ps] for v, ps in preds.items()}
    subsets = {"全部": np.ones(len(test), bool), "非 derived": (test["label_type"] != "derived").to_numpy(),
               "R-inconsistent": test["clean"].to_numpy(), "无同来源 v3.1": (~test["has_v31"]).to_numpy()}
    lines.append("## 1. 打乱 v3.1 标签的负对照（时间划分）\n")
    for name, m in subsets.items():
        idx = np.flatnonzero(m)
        tt = test.iloc[idx].reset_index(drop=True)
        lines += [f"\n### {name}：n = {len(idx):,}\n", "| 版本 | 种子数 | 平均宏 F1（均值 ± 标准差） | 共享 7 指标宏 F1 | AT/SC/SI/SA 宏 F1 | 等级准确率 |", "|---|---|---|---|---|---|"]
        for v, ps in preds.items():
            rs = [evaluate(tt, p.iloc[idx].reset_index(drop=True)) for p in ps]
            mf = [r["mean_macro_f1"] for r in rs]
            sh = np.mean([np.mean([r["per_metric"][k]["macro_f1"] for k in SHARED]) for r in rs])
            nw = np.mean([np.mean([r["per_metric"][k]["macro_f1"] for k in NEW]) for r in rs])
            lines.append(f"| {v} | {len(ps)} | {np.mean(mf):.3f} ± {np.std(mf, ddof=1):.3f} | {sh:.3f} | {nw:.3f} | {np.mean([r['band_acc'] for r in rs]):.3f} |")
        rng = np.random.default_rng(0)
        lines += ["\n配对 bootstrap（A − B；平均宏 F1 / 等级准确率；95% 区间）：\n", "| A − B | 共同种子数 | 平均宏 F1 差 | 等级准确率差 |", "|---|---|---|---|"]
        for a, b in [("v3.1 辅助 5 轮", "打乱 v3.1 辅助 5 轮"), ("打乱 v3.1 辅助 5 轮", "无辅助 5 轮"), ("打乱 v3.1 辅助 5 轮", "无辅助 10 轮"),
                     ("v3.1 辅助 5 轮", "无辅助 5 轮"), ("打乱 v3.1 辅助 5 轮", "CWE 辅助 5 轮"), ("v3.1 辅助 5 轮", "CWE 辅助 5 轮")]:
            k, c0, c1 = boot(t, enc, a, b, idx, rng)
            lines.append(f"| {a} − {b} | {k} | {c0} | {c1} |")
    cm = test["clean"].to_numpy()
    atp = cm & (test["y_AT"] == "P").to_numpy()
    lines += [f"\n### AT：R-inconsistent 子集中真实为 AT:Present 的 {int(atp.sum()):,} 条\n", "| 版本 | 种子数 | 预测为 AT:None 的比例 | 全部测试集中预测为 AT:Present 的比例 |", "|---|---|---|---|"]
    for v, ps in preds.items():
        share = np.mean([(p["AT"].to_numpy()[atp] == "N").mean() for p in ps])
        allp = np.mean([(p["AT"].to_numpy() == "P").mean() for p in ps])
        lines.append(f"| {v} | {len(ps)} | {share:.3f} | {allp:.3f} |")
    lines.append(f"\n（全部测试集中真实为 AT:Present 的比例：{(test['y_AT'] == 'P').mean():.3f}）\n")


def part2(df, lines):
    lines.append("\n## 2. LOSO 划分：无辅助训练 10 轮\n")
    for split in ["VulnCheck", "GitHub_M", "VulDB"]:
        stem = f"T2_loso-{split}_deberta-v3-base_none"
        vers = {"无辅助 5 轮": runs(stem, "_e5_cwinv_sqrt", range(5)), "无辅助 10 轮": runs(stem, "_e10_cwinv_sqrt", range(5)),
                "v3.1 辅助 5 轮": runs(stem, "_aux_e5_cwinv_sqrt", range(5))}
        if not vers["无辅助 10 轮"]:
            lines.append(f"\n### 留出 {split}：10 轮还没有结果\n")
            continue
        test = df[df["source"] == split].reset_index(drop=True)
        ids = test["cve_id"]
        t = Encoded(test, "y_")
        preds = {v: read(p, ids) for v, p in vers.items()}
        enc = {v: [Encoded(p) for p in ps] for v, ps in preds.items()}
        idx = np.arange(len(test))
        lines += [f"\n### 留出 {split}：n = {len(test):,}\n", "| 版本 | 种子数 | 平均宏 F1（均值 ± 标准差） | 等级准确率 | 低估率 |", "|---|---|---|---|---|"]
        for v, ps in preds.items():
            rs = [evaluate(test, p) for p in ps]
            mf = [r["mean_macro_f1"] for r in rs]
            sd = np.std(mf, ddof=1) if len(mf) > 1 else float("nan")
            lines.append(f"| {v} | {len(ps)} | {np.mean(mf):.3f} ± {sd:.3f} | {np.mean([r['band_acc'] for r in rs]):.3f} | "
                         f"{np.mean([r.get('under_rate', float('nan')) for r in rs]):.3f} |")
        rng = np.random.default_rng(0)
        lines += ["\n| A − B | 共同种子数 | 平均宏 F1 差 | 等级准确率差 |", "|---|---|---|---|"]
        for a, b in [("无辅助 10 轮", "无辅助 5 轮"), ("v3.1 辅助 5 轮", "无辅助 10 轮"), ("v3.1 辅助 5 轮", "无辅助 5 轮")]:
            k, c0, c1 = boot(t, enc, a, b, idx, rng)
            lines.append(f"| {a} − {b} | {k} | {c0} | {c1} |")


def part3(df, lines):
    """5% v4 训练标签：正常 v3.1 辅助 vs 打乱 v3.1 辅助（run_review_gpu3.sh），参照全部标签的无辅助模型。"""
    stem = "T2_temporal_deberta-v3-base_none"
    vers = {"5% + v3.1 辅助": runs(stem, "_aux_e5_cwinv_sqrt_frac0.05", range(3)),
            "5% + 打乱 v3.1 辅助": runs(stem, "_auxshuf_e5_cwinv_sqrt_frac0.05", range(3)),
            "全部标签，无辅助 5 轮": runs(stem, "_e5_cwinv_sqrt", range(5)),
            "全部标签，无辅助 10 轮": runs(stem, "_e10_cwinv_sqrt", range(3))}
    lines.append("\n## 3. 5% v4 训练标签下的打乱对照（时间划分）\n")
    if not vers["5% + 打乱 v3.1 辅助"]:
        lines.append("还没有结果。\n")
        return
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    test["clean"] = clean_mask(test)
    ids = test["cve_id"]
    t = Encoded(test, "y_")
    preds = {v: read(p, ids) for v, p in vers.items()}
    enc = {v: [Encoded(p) for p in ps] for v, ps in preds.items()}
    cm = test["clean"].to_numpy()
    atp = cm & (test["y_AT"] == "P").to_numpy()
    for name, m in {"全部": np.ones(len(test), bool), "非 derived": (test["label_type"] != "derived").to_numpy(), "R-inconsistent": cm}.items():
        idx = np.flatnonzero(m)
        tt = test.iloc[idx].reset_index(drop=True)
        lines += [f"\n### {name}：n = {len(idx):,}\n", "| 版本 | 种子数 | 平均宏 F1（均值 ± 标准差） | 等级准确率 |", "|---|---|---|---|"]
        for v, ps in preds.items():
            rs = [evaluate(tt, p.iloc[idx].reset_index(drop=True)) for p in ps]
            mf = [r["mean_macro_f1"] for r in rs]
            sd = np.std(mf, ddof=1) if len(mf) > 1 else float("nan")
            lines.append(f"| {v} | {len(ps)} | {np.mean(mf):.3f} ± {sd:.3f} | {np.mean([r['band_acc'] for r in rs]):.3f} |")
        rng = np.random.default_rng(0)
        lines += ["\n| A − B | 共同种子数 | 平均宏 F1 差 | 等级准确率差 |", "|---|---|---|---|"]
        for a, b in [("5% + v3.1 辅助", "5% + 打乱 v3.1 辅助"), ("5% + 打乱 v3.1 辅助", "全部标签，无辅助 5 轮"),
                     ("5% + 打乱 v3.1 辅助", "全部标签，无辅助 10 轮"), ("5% + v3.1 辅助", "全部标签，无辅助 10 轮")]:
            k, c0, c1 = boot(t, enc, a, b, idx, rng)
            lines.append(f"| {a} − {b} | {k} | {c0} | {c1} |")
    lines += [f"\n### AT：R-inconsistent 子集中真实为 AT:Present 的 {int(atp.sum()):,} 条被预测为 None 的比例\n", "| 版本 | 比例 |", "|---|---|"]
    for v, ps in preds.items():
        lines.append(f"| {v} | {np.mean([(p['AT'].to_numpy()[atp] == 'N').mean() for p in ps]):.3f} |")


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    lines = ["# 第六份审稿意见 M5 的 GPU 实验汇总（自动生成）\n"]
    only = sys.argv[1:]  # 可只跑部分：python src/review_gpu2_summary.py 2 3
    if not only or "1" in only:
        part1(df, lines)
    if not only or "2" in only:
        part2(df, lines)
    if not only or "3" in only:
        part3(df, lines)
    out = OUT if not only else OUT.with_name(f"summary2_part{''.join(sorted(only))}.md")  # 只跑部分时不覆盖完整汇总
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
