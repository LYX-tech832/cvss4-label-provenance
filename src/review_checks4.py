"""第四份模拟审稿意见（10-01）的核查（CPU，几分钟）：迁移增益是否只是学会了规则 R 的换算约定。

在两个"规则 R 无从帮忙"的子集上比较各版本：
- 干净子集：双版本评分且 v4.0 ≠ 规则 R(同来源 v3.1) 的时间划分测试 CVE（2,602 条）；
- 没有同来源 v3.1 的测试 CVE（v4.0 标签无法与规则 R 比对）。
版本：无辅助 / v3.1 辅助（5 轮，种子 0–4；10 轮，种子 0–2）、伪标签、DeBERTa 流水线（种子 0–2）、TF-IDF。
差值为配对 bootstrap（测试 CVE 重抽样 1,000 次，各版本种子平均）。
输出：results/review_checks/summary4.md
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded, fast_scores  # noqa: E402
from baselines_v0 import CUTOFF, M40, evaluate, load, source_type_map  # noqa: E402
from review_checks import clean_mask  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
STEM = "T2_temporal_deberta-v3-base_none"
VERS = {"无辅助 5 轮": ("_e5_cwinv_sqrt", range(5)), "v3.1 辅助 5 轮": ("_aux_e5_cwinv_sqrt", range(5)),
        "无辅助 10 轮": ("_e10_cwinv_sqrt", range(3)), "v3.1 辅助 10 轮": ("_aux_e10_cwinv_sqrt", range(3)),
        "伪标签 5 轮": ("_pseudo_e5_cwinv_sqrt", range(3)), "DeBERTa 流水线": ("_v31only_e5", range(3))}
SHARED = ["AV", "AC", "PR", "UI", "VC", "VI", "VA"]


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    test["clean"] = clean_mask(test)
    ids = test["cve_id"]
    t = Encoded(test, "y_")
    preds = {v: [pd.read_parquet(ENC / f"{STEM}{tag}_s{s}" / "pred_latent.parquet").set_index("cve_id").loc[ids].reset_index() for s in seeds]
             for v, (tag, seeds) in VERS.items()}
    preds["TF-IDF"] = [pd.read_parquet(ROOT / "results" / "baselines_v0" / "predictions" / "T2_temporal_tfidf_lr.parquet").set_index("cve_id").loc[ids].reset_index()]
    enc = {v: [Encoded(p) for p in ps] for v, ps in preds.items()}
    subsets = {"全部（21,900）": np.ones(len(test), bool), "干净子集": test["clean"].to_numpy(),
               "无同来源 v3.1": (~test["has_v31"]).to_numpy(),
               "干净子集，不含 VulnCheck": (test["clean"] & (test["source"] != "VulnCheck")).to_numpy()}
    lines = ["# 第四份审稿意见的核查：规则 R 无从帮忙的子集上的迁移增益（时间划分；自动生成）\n",
             "干净子集 = 双版本评分且 v4.0 ≠ 规则 R(同来源 v3.1)；其中 VulnCheck "
             f"{int((test['clean'] & (test['source'] == 'VulnCheck')).sum()):,} 条、derived {int((test['clean'] & (test['label_type'] == 'derived')).sum())} 条。\n"]
    for name, m in subsets.items():
        idx = np.flatnonzero(m)
        lines += [f"\n## {name}：n = {len(idx):,}\n", "| 版本 | 种子数 | 平均宏 F1 | 共享 7 指标宏 F1 | AT/SC/SI/SA 宏 F1 | 等级准确率 |", "|---|---|---|---|---|---|"]
        tt = test.iloc[idx].reset_index(drop=True)
        for v, ps in preds.items():
            rs = [evaluate(tt, p.iloc[idx].reset_index(drop=True)) for p in ps]
            sh = np.mean([np.mean([r["per_metric"][k]["macro_f1"] for k in SHARED]) for r in rs])
            nw = np.mean([np.mean([r["per_metric"][k]["macro_f1"] for k in ["AT", "SC", "SI", "SA"]]) for r in rs])
            lines.append(f"| {v} | {len(ps)} | {np.mean([r['mean_macro_f1'] for r in rs]):.3f} | {sh:.3f} | {nw:.3f} | {np.mean([r['band_acc'] for r in rs]):.3f} |")
        rng = np.random.default_rng(0)
        lines += ["\n配对 bootstrap（A − B，平均宏 F1 / 等级准确率，95% 区间；两个版本种子数不同时只用共同的种子 0–2）：\n", "| A − B | 平均宏 F1 差 | 等级准确率差 |", "|---|---|---|"]
        for a, b in [("v3.1 辅助 5 轮", "无辅助 5 轮"), ("v3.1 辅助 10 轮", "无辅助 10 轮"), ("伪标签 5 轮", "无辅助 5 轮"),
                     ("v3.1 辅助 5 轮", "伪标签 5 轮"), ("DeBERTa 流水线", "无辅助 5 轮")]:
            k = min(len(enc[a]), len(enc[b]))  # 种子数不同时只比较共同的种子（都从 0 开始），10-01 第五份审稿意见指出原先未匹配

            def d(ix):
                fa = [fast_scores(t, e, ix) for e in enc[a][:k]]
                fb = [fast_scores(t, e, ix) for e in enc[b][:k]]
                return (np.mean([x["mean_macro_f1"] for x in fa]) - np.mean([x["mean_macro_f1"] for x in fb]),
                        np.mean([x["band_acc"] for x in fa]) - np.mean([x["band_acc"] for x in fb]))
            pt = d(idx)
            bs = np.array([d(rng.choice(idx, size=len(idx), replace=True)) for _ in range(1000)])
            lines.append(f"| {a} − {b} | {pt[0]:+.3f} [{np.percentile(bs[:, 0], 2.5):+.3f}, {np.percentile(bs[:, 0], 97.5):+.3f}] | "
                         f"{pt[1]:+.3f} [{np.percentile(bs[:, 1], 2.5):+.3f}, {np.percentile(bs[:, 1], 97.5):+.3f}] |")
    # AT：干净子集中真实值为 AT:Present 的样本，各模型预测成默认值 None 的比例，以及干净子集上 AT 的宏 F1
    from aggregate_seeds import paired_bootstrap  # noqa: E402
    preds["5% + v3.1 辅助"] = [pd.read_parquet(ENC / f"{STEM}_aux_e5_cwinv_sqrt_frac0.05_s{s}" / "pred_latent.parquet").set_index("cve_id").loc[ids].reset_index()
                                for s in range(3)]
    cm = test["clean"].to_numpy()
    atp = cm & (test["y_AT"] == "P").to_numpy()
    lines += [f"\n## AT：干净子集中真实为 AT:Present 的 {int(atp.sum()):,} 条\n", "| 版本 | 种子数 | 预测为 AT:None 的比例 | 干净子集上 AT 的宏 F1 |", "|---|---|---|---|"]
    ct = test[cm].reset_index(drop=True)
    for v, ps in preds.items():
        share = np.mean([(p["AT"].to_numpy()[atp] == "N").mean() for p in ps])
        f1 = np.mean([evaluate(ct, p[cm].reset_index(drop=True))["per_metric"]["AT"]["macro_f1"] for p in ps])
        lines.append(f"| {v} | {len(ps)} | {share:.3f} | {f1:.3f} |")
    # 5% + 辅助 与训练 10 轮、用全部标签的无辅助模型：按子集比较（复用 paired_bootstrap 的"非 derived"口径来指定子集）
    rconv = test["has_v31"].to_numpy() & ~cm & (test["label_type"] != "derived").to_numpy()
    lines += ["\n## 5% + 辅助 − 全部标签无辅助（10 轮）：平均宏 F1 差（配对 bootstrap 1,000 次）\n", "| 子集 | n | 差值 [95%] |", "|---|---|---|"]
    none10 = {s: ENC / f"{STEM}_e10_cwinv_sqrt_s{s}" for s in range(3)}
    aux5p = {s: ENC / f"{STEM}_aux_e5_cwinv_sqrt_frac0.05_s{s}" for s in range(3)}
    for name, m in [("干净子集", cm), ("与规则 R 一致（双版本评分、非 derived）", rconv),
                    ("与规则 R 一致（双版本评分，含 derived）", test["has_v31"].to_numpy() & ~cm)]:
        keep = set(test["cve_id"][m])
        sub = df.assign(label_type=np.where(df["cve_id"].isin(keep), "keep", "derived"))
        r = paired_bootstrap(sub, none10, aux5p)["non_derived"]
        lines.append(f"| {name} | {r['n']:,} | {r['mean_macro_f1'][0]:+.3f} [{r['mean_macro_f1'][1]:+.3f}, {r['mean_macro_f1'][2]:+.3f}] |")
    out = ROOT / "results" / "review_checks" / "summary4.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
