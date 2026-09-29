"""W2 预实验：跨版本迁移（贡献 3 的可行性检验，CPU，T2 只用描述）。

问题：约 15 万条只有 v3.1 标签的 CVE，能否帮助"从描述预测 v4.0"，尤其是在非 derived 标签和 v4 特有指标上？
做法（两阶段堆叠，是编码器多任务学习的廉价代理）：
  阶段 1：只用"有 v3.1、没有 v4.0、且 2026-01-01 之前发布"的 CVE，训练 描述 → 8 个 v3.1 指标的 TF-IDF+LR；
          v4 训练/测试样本都不在阶段 1 的训练集里，所以它们得到的 v3.1 预测都是样本外的。
  阶段 2：v4 分类器的特征 = TF-IDF(描述) + 阶段 1 预测的 v3.1 概率（乘以权重 w 后拼接）。
对照：T2 基线 TF-IDF+LR（不含 v3.1 预测特征）。
划分：时间划分；报告全部、去掉 derived、按标签类型三种口径。
v3.1 标签取 CNA 的第一个 v3.1 向量，没有时取 ADP 的第一个 v3.1 向量。
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import CUTOFF, M31, M40, SEED, evaluate, load, source_type_map  # noqa: E402
from cvss_utils import V31_METRICS, parse_vector  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "results" / "pilot_transfer"
WEIGHTS = [1.0, 3.0]


def v31_pool(before_cutoff=True):
    """只有 v3.1、没有 CNA v4.0 的 CVE（阶段 1 训练集）；默认只取 2026 年前发布的。"""
    df = pd.read_parquet(ROOT / "data" / "processed" / "cve_records.parquet")
    df = df[(df["cna_v40"].str.len() == 0) & df["description"].notna()].copy()
    df["pub"] = pd.to_datetime(df["date_published"], utc=True, errors="coerce")
    if before_cutoff:
        df = df[df["pub"] < CUTOFF]

    def pick(r):
        if len(r["cna_v31"]):
            return parse_vector(r["cna_v31"][0], "3.1")
        if len(r["adp_v31"]):
            return parse_vector(r["adp_v31"][0].split("|", 1)[1], "3.1")
        return None

    v31 = df.apply(pick, axis=1)
    df = df[v31.notna()].copy()
    v31 = v31[v31.notna()]
    for k in M31:
        df["z_" + k] = v31.map(lambda p: p[k])
    cwe = df["cwe_cna"].map(list) + df["cwe_adp"].map(list)
    df["text"] = df["description"].str.strip() + " " + cwe.map(lambda c: " ".join(dict.fromkeys(c)))
    return df


def stage1(pool, texts):
    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=3, max_features=300_000, sublinear_tf=True)
    x = vec.fit_transform(pool["text"])
    xq = vec.transform(texts)
    feats = []
    for k in M31:
        clf = LogisticRegression(C=4.0, max_iter=3000, random_state=SEED).fit(x, pool["z_" + k].values)
        p = np.zeros((xq.shape[0], len(V31_METRICS[k])))
        for j, c in enumerate(clf.classes_):
            p[:, V31_METRICS[k].index(c)] = clf.predict_proba(xq)[:, j]
        feats.append(p)
        print("stage1", k, flush=True)
    return np.hstack(feats)


def stage2(train, test, z_train, z_test, w):
    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=200_000, sublinear_tf=True)
    xtr, xte = vec.fit_transform(train["text"]), vec.transform(test["text"])
    if w > 0:
        xtr = hstack([xtr, csr_matrix(z_train * w)]).tocsr()
        xte = hstack([xte, csr_matrix(z_test * w)]).tocsr()
    pred = {}
    for k in M40:
        clf = LogisticRegression(C=4.0, max_iter=3000, random_state=SEED).fit(xtr, train["y_" + k].values)
        pred[k] = clf.predict(xte)
    return pd.DataFrame(pred)


def report(test, pred):
    types = test["source"].map(source_type_map()).fillna("other").values
    out = {}
    for scope, m in [("all", np.ones(len(test), bool)), ("non_derived", types != "derived")] + [(t, types == t) for t in ["independent", "v4_only", "other"]]:
        r = evaluate(test[m].reset_index(drop=True), pred[m].reset_index(drop=True))
        out[scope] = {"n": int(m.sum()), "mean_f1": r["mean_macro_f1"],
                      "v4_specific_f1": float(np.mean([r["per_metric"][k]["macro_f1"] for k in ["AT", "UI", "SC", "SI", "SA"]])),
                      "exact": r["exact_match"], "band_acc": r["band_acc"], "under_rate": r["under_rate"],
                      "per_metric": {k: r["per_metric"][k]["macro_f1"] for k in M40}}
    return out


def main():
    df = load()
    train, test = df[df["pub"] < CUTOFF].reset_index(drop=True), df[df["pub"] >= CUTOFF].reset_index(drop=True)
    pool = v31_pool()
    print(f"stage1 pool (v3.1-only, pre-2026): {len(pool):,}", flush=True)
    z = stage1(pool, list(train["text"]) + list(test["text"]))
    z_tr, z_te = z[:len(train)], z[len(train):]
    results = {"n_stage1_pool": len(pool)}
    for w in [0.0] + WEIGHTS:
        name = "baseline_tfidf" if w == 0 else f"transfer_w{w:g}"
        results[name] = report(test, stage2(train, test, z_tr, z_te, w))
        r = results[name]
        print(name, {s: (round(v["mean_f1"], 3), round(v["v4_specific_f1"], 3), round(v["band_acc"], 3), round(v["under_rate"], 3)) for s, v in r.items()}, flush=True)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "metrics.json").write_text(json.dumps(results, indent=1, ensure_ascii=False), encoding="utf-8")
    lines = [f"# 预实验：跨版本迁移（T2，两阶段堆叠；阶段 1 训练集 = {len(pool):,} 条只有 v3.1 的 2026 年前 CVE；单次运行）\n",
             "单元格 = 11 指标平均 F1 / v4 特有指标平均 F1 / 等级准确率 / 低估率\n",
             "| 方法 | 全部 | 去掉 derived | independent | v4_only | other |", "|---|---|---|---|---|---|"]
    for name, r in results.items():
        if name == "n_stage1_pool":
            continue
        lines.append(f"| {name} | " + " | ".join(f"{r[s]['mean_f1']:.3f} / {r[s]['v4_specific_f1']:.3f} / {r[s]['band_acc']:.3f} / {r[s]['under_rate']:.3f}"
                                                 for s in ["all", "non_derived", "independent", "v4_only", "other"]) + " |")
    (OUT_DIR / "summary.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
