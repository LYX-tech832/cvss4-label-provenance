"""第三轮审稿意见（10-03）的 CPU 分析（约 20–30 分钟，主要是 TF-IDF 重拟合）：

A. 基率校正（M2）：时间划分测试集上，各标签类型与主要来源的"最常见等级占比"（基率）、各方法的等级准确率、
   两者之差，以及严重性等级的 Cohen's κ。说明 VulDB 上分数高主要来自基率高。
B. 训练端实验（M2）：TF-IDF 基线的训练集去掉 VulDB 的标签后，在非 derived 测试标签及各来源上的变化（配对 bootstrap）。
C. 滚动时间切点（M1/M4）：TF-IDF 基线在 5 个截止日期上各训练一次，在随后一个季度上测试，
   比较"全部标签"与"去掉 VulDB"的结果（来源分型只在 2026 年前的数据上做过，这里用"是否 VulDB"代替）。
输出：results/review_checks/summary8.md
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import cohen_kappa_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded, fast_scores  # noqa: E402
from baselines_v0 import CUTOFF, evaluate, load, pred_tfidf_lr, source_type_map  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
OUT = ROOT / "results" / "review_checks" / "summary8.md"
rng = np.random.default_rng(0)


def read(path, ids):
    return pd.read_parquet(path).set_index("cve_id").loc[ids].reset_index()


def part_a(df, test, lines):
    ids = test["cve_id"]
    t = Encoded(test, "y_")
    methods = {"TF-IDF + LR": [read(ROOT / "results" / "baselines_v0" / "predictions" / "T2_temporal_tfidf_lr.parquet", ids)],
               "DeBERTa（25 轮，5 种子）": [read(ENC / f"T2_temporal_deberta-v3-base_none_e25_cwinv_sqrt_s{s}" / "pred_latent.parquet", ids) for s in range(5)],
               "DeBERTa + 辅助（5 种子）": [read(ENC / f"T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s{s}" / "pred_latent.parquet", ids) for s in range(5)]}
    enc = {m: [Encoded(p) for p in ps] for m, ps in methods.items()}
    groups = [("全部", np.ones(len(test), bool)), ("非 derived", (test["label_type"] != "derived").to_numpy())]
    groups += [(f"类型 {k}", (test["label_type"] == k).to_numpy()) for k in ["derived", "independent", "v4_only", "other"]]
    groups += [(f"来源 {s}", (test["source"] == s).to_numpy()) for s in ["VulDB", "VulnCheck", "GitHub_M"]]
    lines += ["## A. 基率校正：严重性等级（时间划分测试集）\n",
              "基率 = 该组真实等级中最常见等级的占比（总猜这个等级能得到的等级准确率）。κ = 等级的 Cohen's κ（不加权）。DeBERTa 为 5 个种子的平均。\n",
              "| 组 | n | 基率 | " + " | ".join(f"{m}：准确率 / 超出基率 / κ" for m in methods) + " |", "|---|---|---|" + "---|" * len(methods)]
    for name, m in groups:
        idx = np.flatnonzero(m)
        tb = t.band[idx]
        base = np.bincount(tb[tb >= 0]).max() / len(tb)
        cells = []
        for mth in methods:
            acc = np.mean([(e.band[idx] == tb).mean() for e in enc[mth]])
            kap = np.mean([cohen_kappa_score(tb, e.band[idx]) for e in enc[mth]])
            cells.append(f"{acc:.3f} / {acc - base:+.3f} / {kap:.3f}")
        lines.append(f"| {name} | {len(idx):,} | {base:.3f} | " + " | ".join(cells) + " |")


def boot_diff(t, ea, eb, idx, B=1000):
    def d(ix):
        a, b = fast_scores(t, ea, ix), fast_scores(t, eb, ix)
        return a["mean_macro_f1"] - b["mean_macro_f1"], a["band_acc"] - b["band_acc"]
    pt = d(idx)
    bs = np.array([d(rng.choice(idx, size=len(idx), replace=True)) for _ in range(B)])
    return [f"{pt[j]:+.3f} [{np.percentile(bs[:, j], 2.5):+.3f}, {np.percentile(bs[:, j], 97.5):+.3f}]" for j in range(2)]


def part_b(df, test, lines):
    train = df[df["pub"] < CUTOFF]
    ids = test["cve_id"]
    full = read(ROOT / "results" / "baselines_v0" / "predictions" / "T2_temporal_tfidf_lr.parquet", ids)
    sub = train[train["source"] != "VulDB"]
    nov = pred_tfidf_lr(sub, test, with_v31=False).reset_index(drop=True)
    nov.insert(0, "cve_id", ids.values)
    nov.to_parquet(ROOT / "results" / "review_checks" / "T2_temporal_tfidf_lr_noVulDBtrain.parquet")
    t, ef, en = Encoded(test, "y_"), Encoded(full), Encoded(nov)
    lines += ["\n## B. 训练集去掉 VulDB 的标签（TF-IDF + LR；测试集不变）\n",
              f"训练标签：全部 {len(train):,} 条；去掉 VulDB 后 {len(sub):,} 条（VulDB {len(train) - len(sub):,} 条，占 {(len(train) - len(sub)) / len(train):.1%}）。\n",
              "| 测试口径 | n | 全部训练：平均宏 F1 / 等级准确率 | 去掉 VulDB 训练 | 差值（去掉 − 全部）：平均宏 F1 | 等级准确率 |", "|---|---|---|---|---|---|"]
    groups = [("非 derived", (test["label_type"] != "derived").to_numpy()), ("derived（VulDB）", (test["label_type"] == "derived").to_numpy()),
              ("类型 independent", (test["label_type"] == "independent").to_numpy()), ("类型 v4_only", (test["label_type"] == "v4_only").to_numpy()),
              ("类型 other", (test["label_type"] == "other").to_numpy()), ("来源 VulnCheck", (test["source"] == "VulnCheck").to_numpy()),
              ("来源 GitHub_M", (test["source"] == "GitHub_M").to_numpy())]
    for name, m in groups:
        idx = np.flatnonzero(m)
        a, b = fast_scores(t, ef, idx), fast_scores(t, en, idx)
        d = boot_diff(t, en, ef, idx)
        lines.append(f"| {name} | {len(idx):,} | {a['mean_macro_f1']:.3f} / {a['band_acc']:.3f} | {b['mean_macro_f1']:.3f} / {b['band_acc']:.3f} | {d[0]} | {d[1]} |")


def part_c(df, lines):
    lines += ["\n## C. 滚动时间切点（TF-IDF + LR；在截止日期之前的标签上训练，在随后一个季度上测试）\n",
              "| 截止日期 | 训练 | 测试 | 测试中 VulDB 占比 | 全部：平均宏 F1 / 等级准确率 | 去掉 VulDB | 等级准确率之差 |", "|---|---|---|---|---|---|---|"]
    cuts = ["2025-07-01", "2025-10-01", "2026-01-01", "2026-04-01", "2026-07-01"]
    for c in cuts:
        c0 = pd.Timestamp(c, tz="UTC")
        c1 = c0 + pd.DateOffset(months=3)
        tr, te = df[df["pub"] < c0], df[(df["pub"] >= c0) & (df["pub"] < c1)].reset_index(drop=True)
        pred = pred_tfidf_lr(tr, te, with_v31=False).reset_index(drop=True)
        nv = (te["source"] != "VulDB").to_numpy()
        ra = evaluate(te, pred)
        rb = evaluate(te[nv].reset_index(drop=True), pred[nv].reset_index(drop=True))
        lines.append(f"| {c} | {len(tr):,} | {len(te):,} | {1 - nv.mean():.1%} | {ra['mean_macro_f1']:.3f} / {ra['band_acc']:.3f} | "
                     f"{rb['mean_macro_f1']:.3f} / {rb['band_acc']:.3f} | {ra['band_acc'] - rb['band_acc']:+.3f} |")
        print("done", c, flush=True)


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    lines = ["# 第三轮审稿意见的 CPU 分析（自动生成）\n"]
    part_a(df, test, lines)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    part_b(df, test, lines)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    part_c(df, lines)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
