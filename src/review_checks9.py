"""第四轮审稿意见（10-03 晚）的 CPU 分析（约 10 分钟）：

A. 决定性对照（M1）：VulDB 的 v3.1 标签是否同样比其他来源容易预测？
   同一批 CVE、同一个模型（TF-IDF + LR）、同样的训练/测试划分（T1 的双版本评分 CVE：2026 年前训练，2026 年测试），
   分别预测同一 CNA 给的 v3.1 向量和 v4.0 向量，按来源报告严重性等级的基率、准确率、Cohen's κ 和平均宏 F1。
   如果 VulDB 的 v3.1 标签同样更容易预测，评测差异就是来源效应，而不是 v4.0 标签"派生"造成的。
B. VulnCheck 的回填（M2）：时间划分测试集中各来源的 CVE 编号年份分布。
C. 按来源宏平均（M2）：时间划分测试集上，各来源（≥ 30 条测试 CVE）等权平均后的结果与辅助任务的增益。
D. T1 测试集的标签类型构成（问题 9）。
E. 去掉回填的测试 CVE（编号年份早于 2025）后的主要结果（M2）。
输出：results/review_checks/summary10.md
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd
from cvss import CVSS3
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import cohen_kappa_score, f1_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded, fast_scores  # noqa: E402
from baselines_v0 import CUTOFF, M31, M40, SEED, load, source_type_map  # noqa: E402
from cvss_utils import V31_METRICS, V40_METRICS  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
OUT = ROOT / "results" / "review_checks" / "summary10.md"
rng = np.random.default_rng(0)
BANDS = ["None", "Low", "Medium", "High", "Critical"]


def band31(frame, prefix):
    vec = "CVSS:3.1/" + frame[[prefix + k for k in M31]].apply(lambda r: "/".join(f"{k}:{v}" for k, v in zip(M31, r)), axis=1)
    cache = {}
    return np.array([cache.setdefault(v, BANDS.index(CVSS3(v).severities()[0])) for v in vec])


def fit_predict(train_text, test_text, ys):
    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=200_000, sublinear_tf=True)
    xtr, xte = vec.fit_transform(train_text), vec.transform(test_text)
    out = {}
    for k, y in ys.items():
        out[k] = [y[0]] * xte.shape[0] if len(set(y)) == 1 else LogisticRegression(C=4.0, max_iter=3000, random_state=SEED).fit(xtr, y).predict(xte)
    return pd.DataFrame(out)


def macro_f1(true, pred, values):
    return float(np.mean([f1_score(true[k], pred[k], labels=values[k], average="macro", zero_division=0) for k in pred.columns]))


def part_a(df, lines):
    d = df[df["has_v31"]]
    tr, te = d[d["pub"] < CUTOFF], d[d["pub"] >= CUTOFF].reset_index(drop=True)
    p31 = fit_predict(tr["text"], te["text"], {k: tr["x31_" + k].values for k in M31})
    p40 = fit_predict(tr["text"], te["text"], {k: tr["y_" + k].values for k in M40})
    t31 = te[["x31_" + k for k in M31]].set_axis(M31, axis=1)
    t40 = te[["y_" + k for k in M40]].set_axis(M40, axis=1)
    b31t, b31p = band31(te, "x31_"), band31(p31.add_prefix("p_"), "p_")
    e_t, e_p = Encoded(te, "y_"), Encoded(p40.assign(cve_id=te["cve_id"]))
    lines += ["## A. 同一批 CVE 上，v3.1 标签与 v4.0 标签的可预测性（TF-IDF + LR；T1 的双版本评分 CVE）\n",
              f"训练：2026 年前的双版本评分 CVE {len(tr):,} 条；测试：2026 年的 {len(te):,} 条。两个模型的输入、训练 CVE、测试 CVE 完全相同，只是标签换了版本。\n",
              "| 测试标签的来源 | n | v3.1：基率 / 等级准确率 / κ / 平均宏 F1（8 指标） | v4.0：基率 / 等级准确率 / κ / 平均宏 F1（11 指标） |", "|---|---|---|---|"]
    groups = [("VulDB", (te["source"] == "VulDB").to_numpy()), ("其他来源合计", (te["source"] != "VulDB").to_numpy()),
              ("VulnCheck", (te["source"] == "VulnCheck").to_numpy()), ("VulDB、VulnCheck 以外", (~te["source"].isin(["VulDB", "VulnCheck"])).to_numpy())]
    for name, m in groups:
        idx = np.flatnonzero(m)
        base31 = np.bincount(b31t[idx]).max() / len(idx)
        acc31 = (b31t[idx] == b31p[idx]).mean()
        k31 = cohen_kappa_score(b31t[idx], b31p[idx])
        f31 = macro_f1(t31.iloc[idx], p31.iloc[idx], V31_METRICS)
        tb, pb = e_t.band[idx], e_p.band[idx]
        base40 = np.bincount(tb[tb >= 0]).max() / len(idx)
        acc40 = (tb == pb).mean()
        k40 = cohen_kappa_score(tb, pb)
        f40 = macro_f1(t40.iloc[idx], p40.iloc[idx], V40_METRICS)
        lines.append(f"| {name} | {len(idx):,} | {base31:.3f} / {acc31:.3f} / {k31:.3f} / {f31:.3f} | {base40:.3f} / {acc40:.3f} / {k40:.3f} / {f40:.3f} |")
    lines.append("\n（宏 F1 在每个指标的全部取值上平均，未出现的取值记 0，与论文口径一致。）")


def part_b(test, lines):
    yr = test["cve_id"].str.extract(r"CVE-(\d{4})-")[0].astype(int)
    lines += ["\n## B. 时间划分测试集（2026 年发布）的 CVE 编号年份\n", "| 来源 | n | 编号年份 < 2025 | 编号年份 = 2025 | 编号年份 = 2026 |", "|---|---|---|---|---|"]
    for name, m in [("VulnCheck", test["source"] == "VulnCheck"), ("VulDB", test["source"] == "VulDB"), ("GitHub_M", test["source"] == "GitHub_M"),
                    ("其他来源", ~test["source"].isin(["VulnCheck", "VulDB", "GitHub_M"])), ("全部", pd.Series(True, index=test.index))]:
        y = yr[m]
        lines.append(f"| {name} | {int(m.sum()):,} | {(y < 2025).mean():.1%} | {(y == 2025).mean():.1%} | {(y == 2026).mean():.1%} |")


def part_c(test, lines):
    ids = test["cve_id"]
    t = Encoded(test, "y_")

    def enc(path):
        return Encoded(pd.read_parquet(path).set_index("cve_id").loc[ids].reset_index())
    methods = {"多数类": [enc(ROOT / "results" / "baselines_v0" / "predictions" / "T2_temporal_majority.parquet")],
               "TF-IDF + LR": [enc(ROOT / "results" / "baselines_v0" / "predictions" / "T2_temporal_tfidf_lr.parquet")],
               "DeBERTa（25 轮）": [enc(ENC / f"T2_temporal_deberta-v3-base_none_e25_cwinv_sqrt_s{s}" / "pred_latent.parquet") for s in range(5)],
               "DeBERTa + 辅助": [enc(ENC / f"T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s{s}" / "pred_latent.parquet") for s in range(5)]}
    src = test["source"].to_numpy()
    counts = test["source"].value_counts()
    lines.append("\n## C. 按来源宏平均（时间划分测试集；每个来源等权）\n")
    for min_n in (30, 100):
        keep = [s for s, n in counts.items() if n >= min_n]
        per = {m: {} for m in methods}
        for s in keep:
            idx = np.flatnonzero(src == s)
            for m, es in methods.items():
                rs = [fast_scores(t, e, idx) for e in es]
                per[m][s] = {k: np.mean([r[k] for r in rs]) for k in ("mean_macro_f1", "band_acc", "under_rate")}
        n_cve = int(sum(counts[s] for s in keep))
        lines += [f"\n测试 CVE ≥ {min_n} 条的来源：{len(keep)} 个（覆盖 {n_cve:,} / {len(test):,} 条）\n", "| 方法 | 平均宏 F1 | 等级准确率 | 低估率 |", "|---|---|---|---|"]
        for m in methods:
            lines.append(f"| {m} | " + " | ".join(f"{np.mean([per[m][s][k] for s in keep]):.3f}" for k in ("mean_macro_f1", "band_acc", "under_rate")) + " |")
        d = np.array([per["DeBERTa + 辅助"][s]["mean_macro_f1"] - per["DeBERTa（25 轮）"][s]["mean_macro_f1"] for s in keep])
        db = np.array([per["DeBERTa + 辅助"][s]["band_acc"] - per["DeBERTa（25 轮）"][s]["band_acc"] for s in keep])
        bs = np.array([[d[i].mean(), db[i].mean()] for i in (rng.integers(len(keep), size=len(keep)) for _ in range(2000))])
        lines.append(f"\n辅助 − DeBERTa（25 轮），按来源宏平均：平均宏 F1 {d.mean():+.3f} [{np.percentile(bs[:, 0], 2.5):+.3f}, {np.percentile(bs[:, 0], 97.5):+.3f}]"
                     f"（来源重抽样）；辅助更好的来源 {int((d > 0).sum())} / {len(keep)}；等级准确率 {db.mean():+.3f} [{np.percentile(bs[:, 1], 2.5):+.3f}, {np.percentile(bs[:, 1], 97.5):+.3f}]。")
        dt = np.array([per["DeBERTa + 辅助"][s]["mean_macro_f1"] - per["TF-IDF + LR"][s]["mean_macro_f1"] for s in keep])
        lines.append(f"辅助 − TF-IDF，按来源宏平均：平均宏 F1 {dt.mean():+.3f}；辅助更好的来源 {int((dt > 0).sum())} / {len(keep)}。")


def part_e(test, lines):
    ids = test["cve_id"]
    t = Encoded(test, "y_")

    def enc(path):
        return Encoded(pd.read_parquet(path).set_index("cve_id").loc[ids].reset_index())
    es = {"TF-IDF + LR": [enc(ROOT / "results" / "baselines_v0" / "predictions" / "T2_temporal_tfidf_lr.parquet")],
          "DeBERTa（25 轮）": [enc(ENC / f"T2_temporal_deberta-v3-base_none_e25_cwinv_sqrt_s{s}" / "pred_latent.parquet") for s in range(5)],
          "DeBERTa + 辅助": [enc(ENC / f"T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s{s}" / "pred_latent.parquet") for s in range(5)]}
    old = (test["cve_id"].str.extract(r"CVE-(\d{4})-")[0].astype(int) < 2025).to_numpy()
    nd = (test["label_type"] != "derived").to_numpy()
    lines += ["\n## E. 去掉回填的测试 CVE（编号年份早于 2025）后的主要结果\n",
              f"去掉 {int(old.sum()):,} 条（其中 VulnCheck {int((old & (test['source'] == 'VulnCheck').to_numpy()).sum()):,} 条）。平均宏 F1 / 等级准确率：\n",
              "| 范围 | n | TF-IDF + LR | DeBERTa（25 轮） | DeBERTa + 辅助 | 辅助 − DeBERTa（宏 F1）[95%] |", "|---|---|---|---|---|---|"]
    for name, m in [("全部测试集", np.ones(len(test), bool)), ("全部，去掉回填", ~old), ("非 derived", nd), ("非 derived，去掉回填", nd & ~old),
                    ("VulnCheck", (test["source"] == "VulnCheck").to_numpy()), ("VulnCheck，去掉回填", (test["source"] == "VulnCheck").to_numpy() & ~old),
                    ("VulnCheck，只看回填", (test["source"] == "VulnCheck").to_numpy() & old)]:
        idx = np.flatnonzero(m)

        def f(ix, k, key="mean_macro_f1"):
            return np.mean([fast_scores(t, e, ix)[key] for e in es[k]])
        cells = [f"{f(idx, k):.3f} / {f(idx, k, 'band_acc'):.3f}" for k in es]
        bs = [f(ix, "DeBERTa + 辅助") - f(ix, "DeBERTa（25 轮）") for ix in (rng.choice(idx, size=len(idx), replace=True) for _ in range(1000))]
        d = f(idx, "DeBERTa + 辅助") - f(idx, "DeBERTa（25 轮）")
        lines.append(f"| {name} | {len(idx):,} | " + " | ".join(cells) + f" | {d:+.3f} [{np.percentile(bs, 2.5):+.3f}, {np.percentile(bs, 97.5):+.3f}] |")


def part_d(df, lines):
    te = df[(df["pub"] >= CUTOFF) & df["has_v31"]]
    lines += ["\n## D. T1 测试集（2026 年、双版本评分）的标签类型\n", "；".join(f"{k} {v:,}" for k, v in te["label_type"].value_counts().items()) + f"；合计 {len(te):,}。",
              "v4-only 类型的 CNA 按定义双版本评分不到 5%；它们在 2026 年的双版本评分 CVE："
              + f"{int((te['label_type'] == 'v4_only').sum())} 条（" + "、".join(f"{s} {n}" for s, n in te.loc[te['label_type'] == 'v4_only', 'source'].value_counts().items()) + "）。"]


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    lines = ["# 第四轮审稿意见的 CPU 分析（自动生成）\n"]
    for step in (lambda: part_a(df, lines), lambda: part_b(test, lines), lambda: part_c(test, lines), lambda: part_d(df, lines), lambda: part_e(test, lines)):
        step()
        OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
