"""W2 基线 v0（纯 CPU）：多数类、规则换算、条件映射、TF-IDF + 逻辑回归。

任务：预测 CNA 给出的 CVSS v4.0 基础向量（11 个指标）。
  T1 版本迁移：输入 = 描述 + 同一 CNA 给出的 v3.1 向量（只用同时有两版的 CVE）
  T2 从零评分：输入 = 描述（所有有 v4.0 的 CVE）
划分：
  temporal  训练 = 2026-01-01 之前发布；测试 = 2026-01-01 及之后
  loso:<源>  留一来源：测试 = 该来源的全部 CVE；训练 = 其余来源（不分时间）
输出：results/baselines_v0/summary.md、metrics.json、predictions/*.parquet

用法（在 F:\\lunwen2 目录下）：python src/baselines_v0.py
"""

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
from cvss import CVSS4
from scipy.sparse import hstack
from scipy.stats import spearmanr
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score
from sklearn.preprocessing import OneHotEncoder

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cvss_utils import V31_METRICS, V40_METRICS, parse_vector  # noqa: E402
from rq1_stats import rule_convert  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "results" / "baselines_v0"
SEED = 0
CUTOFF = pd.Timestamp("2026-01-01", tz="UTC")
LOSO_SOURCES = ["VulDB", "VulnCheck", "GitHub_M"]
M40 = list(V40_METRICS)
M31 = list(V31_METRICS)


def load():
    df = pd.read_parquet(ROOT / "data" / "processed" / "cve_records.parquet")
    df = df[(df["cna_v40"].str.len() > 0) & df["description"].notna()].copy()
    df["pub"] = pd.to_datetime(df["date_published"], utc=True, errors="coerce")
    df["source"] = df["cna_short_name"].fillna("UNKNOWN")
    v40 = df["cna_v40"].map(lambda v: parse_vector(v[0], "4.0"))
    v31 = df["cna_v31"].map(lambda v: parse_vector(v[0], "3.1") if len(v) else None)
    for k in M40:
        df["y_" + k] = v40.map(lambda p: p[k] if p else None)
    for k in M31:
        df["x31_" + k] = v31.map(lambda p: p[k] if p else None)
    df["has_v31"] = v31.notna()
    cwe = df["cwe_cna"].map(list) + df["cwe_adp"].map(list)
    df["text"] = df["description"].str.strip() + " " + cwe.map(lambda c: " ".join(dict.fromkeys(c)))
    return df.dropna(subset=["y_AV"]).reset_index(drop=True)


_score_cache = {}
SEVERITY_ORDER = {"None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def v4_score(vec):
    """返回 (分数, 严重性等级)；等级取 FIRST 定性划分（None/Low/Medium/High/Critical），由 cvss 库给出。"""
    if vec not in _score_cache:
        try:
            c = CVSS4(vec)
            _score_cache[vec] = (float(c.base_score), c.severity)
        except Exception:
            _score_cache[vec] = (np.nan, None)
    return _score_cache[vec]


def to_vector(row):
    return "CVSS:4.0/" + "/".join(f"{k}:{row[k]}" for k in M40)


def evaluate(true_df, pred_df):
    """逐指标 Accuracy / Macro-F1；整向量完全匹配；v4.0 分数 MAE（官方公式，经 cvss 库计算）；
    以及"下游决策"指标：严重性等级准确率、低估率（预测等级低于真实等级）、
    High+Critical 召回率（真实为高危及以上、预测也为高危及以上的比例）、分数的 Spearman 秩相关。"""
    res = {"n": len(true_df), "per_metric": {}}
    for k in M40:
        t, p = true_df["y_" + k].values, pred_df[k].values
        res["per_metric"][k] = {
            "acc": accuracy_score(t, p),
            "macro_f1": f1_score(t, p, average="macro", labels=V40_METRICS[k], zero_division=0),
        }
    res["mean_macro_f1"] = float(np.mean([v["macro_f1"] for v in res["per_metric"].values()]))
    true_vec = true_df[["y_" + k for k in M40]].set_axis(M40, axis=1).apply(to_vector, axis=1)
    pred_vec = pred_df[M40].apply(to_vector, axis=1)
    res["exact_match"] = float((true_vec.values == pred_vec.values).mean())
    t_sc = [v4_score(v) for v in true_vec.values]
    p_sc = [v4_score(v) for v in pred_vec.values]
    ts, ps = np.array([s for s, _ in t_sc]), np.array([s for s, _ in p_sc])
    tb = np.array([SEVERITY_ORDER.get(b, -1) for _, b in t_sc])
    pb = np.array([SEVERITY_ORDER.get(b, -1) for _, b in p_sc])
    res["score_mae"] = float(np.nanmean(np.abs(ts - ps)))
    res["band_acc"] = float((tb == pb).mean())
    res["under_rate"] = float((pb < tb).mean())
    hc = tb >= SEVERITY_ORDER["High"]
    res["hc_recall"] = float((pb[hc] >= SEVERITY_ORDER["High"]).mean()) if hc.any() else float("nan")
    # 预测分数全相同时秩相关无定义，记为 NaN
    res["spearman"] = float(spearmanr(ts, ps, nan_policy="omit").correlation) if len(ts) > 2 and np.nanstd(ps) > 0 and np.nanstd(ts) > 0 else float("nan")
    return res


# ---------------- 各基线 ----------------

def pred_majority(train, test):
    return pd.DataFrame({k: [train["y_" + k].mode()[0]] * len(test) for k in M40}, index=test.index)


def pred_rule(train, test):
    rows = [rule_convert({k: r["x31_" + k] for k in M31}) for _, r in test.iterrows()]
    return pd.DataFrame(rows, index=test.index)[M40]


def pred_cond_map(train, test):
    """从训练集学"整个 v3.1 向量 → 各 v4 指标的众数"；没见过的 v3.1 向量回退到单指标对应关系，再回退到多数类。"""
    key = lambda d: d[["x31_" + k for k in M31]].astype(str).agg("/".join, axis=1)  # noqa: E731
    corr = {"AV": "AV", "AC": "AC", "PR": "PR", "UI": "UI", "VC": "C", "VI": "I", "VA": "A", "SC": "S", "SI": "S", "SA": "S", "AT": "AC"}
    tr_key, te_key = key(train), key(test)
    out = {}
    for k in M40:
        full = train.groupby(tr_key)["y_" + k].agg(lambda s: s.mode()[0]).to_dict()
        single = train.groupby("x31_" + corr[k])["y_" + k].agg(lambda s: s.mode()[0]).to_dict()
        maj = train["y_" + k].mode()[0]
        out[k] = [full.get(kk, single.get(x, maj)) for kk, x in zip(te_key, test["x31_" + corr[k]])]
    return pd.DataFrame(out, index=test.index)


def pred_tfidf_lr(train, test, with_v31):
    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=200_000, sublinear_tf=True)
    xtr, xte = vec.fit_transform(train["text"]), vec.transform(test["text"])
    if with_v31:
        enc = OneHotEncoder(handle_unknown="ignore")
        cols = ["x31_" + k for k in M31]
        xtr = hstack([xtr, enc.fit_transform(train[cols].astype(str))]).tocsr()
        xte = hstack([xte, enc.transform(test[cols].astype(str))]).tocsr()
    out = {}
    for k in M40:
        y = train["y_" + k].values
        if len(set(y)) == 1:
            out[k] = [y[0]] * len(test)
            continue
        clf = LogisticRegression(C=4.0, max_iter=3000, random_state=SEED)
        out[k] = clf.fit(xtr, y).predict(xte)
    return pd.DataFrame(out, index=test.index)


def splits(df):
    yield "temporal", df[df["pub"] < CUTOFF], df[df["pub"] >= CUTOFF]
    for s in LOSO_SOURCES:
        yield f"loso:{s}", df[df["source"] != s], df[df["source"] == s]


def source_type_map():
    """来源分型（label_provenance.py 用 2026 年之前的数据得出）；没有该文件时返回空表。"""
    p = ROOT / "results" / "label_provenance" / "source_types.json"
    return {s: v["type"] for s, v in json.loads(p.read_text(encoding="utf-8")).items()} if p.exists() else {}


SHORT = ["n", "mean_macro_f1", "exact_match", "score_mae", "band_acc", "under_rate", "hc_recall", "spearman"]


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "predictions").mkdir(exist_ok=True)
    results = defaultdict(dict)
    for task in ["T1", "T2"]:
        data = df[df["has_v31"]] if task == "T1" else df
        for split, train, test in splits(data):
            if len(test) == 0 or len(train) == 0:
                continue
            methods = {"majority": pred_majority, "tfidf_lr": lambda a, b: pred_tfidf_lr(a, b, with_v31=(task == "T1"))}
            if task == "T1":
                methods = {"majority": pred_majority, "rule_R": pred_rule, "cond_map": pred_cond_map, **{"tfidf_lr+v31": methods["tfidf_lr"]}}
            for name, fn in methods.items():
                pred = fn(train, test)
                r = evaluate(test, pred)
                r["n_train"] = len(train)
                # 测试集按来源拆分（只报前 3 大来源 + 其余）
                by_src = {}
                top = test["source"].value_counts().head(3).index.tolist()
                for s in top + ["OTHER"]:
                    m = ~test["source"].isin(top) if s == "OTHER" else test["source"] == s
                    if m.sum() >= 30:
                        by_src[s] = evaluate(test[m], pred[m])
                r["by_source"] = {s: {k: v[k] for k in SHORT} for s, v in by_src.items()}
                # 测试集按标签类型拆分（derived / independent / v4_only / other）
                r["by_type"] = {}
                for t in ["derived", "independent", "v4_only", "other"]:
                    m = test["label_type"] == t
                    if m.sum() >= 30:
                        r["by_type"][t] = {k: v for k, v in evaluate(test[m], pred[m]).items() if k in SHORT} | {
                            "v4_specific_f1": float(np.mean([evaluate(test[m], pred[m])["per_metric"][k]["macro_f1"] for k in ["AT", "UI", "SC", "SI", "SA"]]))}
                results[f"{task}|{split}"][name] = r
                pred.assign(cve_id=test["cve_id"].values, source=test["source"].values).to_parquet(
                    OUT_DIR / "predictions" / f"{task}_{split.replace(':', '-')}_{name}.parquet", index=False)
                print(f"{task:3s} {split:18s} {name:14s} n_tr={len(train):6d} n_te={len(test):6d} "
                      f"meanF1={r['mean_macro_f1']:.3f} exact={r['exact_match']:.3f} MAE={r['score_mae']:.3f}", flush=True)

    (OUT_DIR / "metrics.json").write_text(json.dumps(results, indent=1, ensure_ascii=False), encoding="utf-8")
    write_summary(results)


def write_summary(results):
    lines = ["# 基线 v0 结果（CPU，自动生成）\n",
             "指标：meanF1 = 11 个 v4 指标 Macro-F1 的平均；exact = 11 个指标全对的比例；MAE = v4.0 分数平均绝对误差；",
             "band = 严重性等级准确率；under = 低估率（预测等级 < 真实等级）；HC-rec = 真实为 High/Critical 时预测也为 High/Critical 的比例；ρ = 分数 Spearman 秩相关\n"]
    for key, methods in results.items():
        task, split = key.split("|")
        any_r = next(iter(methods.values()))
        lines.append(f"\n## {task} · {split}（训练 {any_r['n_train']:,} / 测试 {any_r['n']:,}）\n")
        lines.append("| 方法 | meanF1 | exact | MAE | band | under | HC-rec | ρ | " + " | ".join(f"F1-{k}" for k in M40) + " |")
        lines.append("|---" * (8 + len(M40)) + "|")
        for name, r in methods.items():
            pm = r["per_metric"]
            lines.append(f"| {name} | {r['mean_macro_f1']:.3f} | {r['exact_match']:.3f} | {r['score_mae']:.2f} | {r['band_acc']:.3f} | "
                         f"{r['under_rate']:.3f} | {r['hc_recall']:.3f} | {r['spearman']:.3f} | " + " | ".join(f"{pm[k]['macro_f1']:.2f}" for k in M40) + " |")
        lines.append("\n按标签类型拆分（meanF1 / v4 特有指标 F1 / 等级准确率 / 低估率）：")
        for name, r in methods.items():
            lines.append(f"- {name}：" + "；".join(f"{t}(n={v['n']:,}) {v['mean_macro_f1']:.3f}/{v['v4_specific_f1']:.3f}/{v['band_acc']:.3f}/{v['under_rate']:.3f}"
                                                   for t, v in r["by_type"].items()))
    (OUT_DIR / "summary.md").write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
