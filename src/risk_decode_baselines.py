"""对 TF-IDF 基线和流水线（规则 R）也做风险敏感解码（CPU），回应"解码只用在 DeBERTa 上，比较不公平"。

与 risk_decode.py 相同的规则和 α 选择：候选集 = 概率 ≥ α × 最大概率的类别，取其中最严重的；
在验证集平均宏 F1 比 argmax 下降不超过 0.01 的 α 中，选验证集低估率最低的。
- TF-IDF：用训练部分的前 90%（按发布日期）训练一个模型，在最后 10%（验证集，与 DeBERTa 相同）上选 α；
  测试集的概率来自用全部训练部分训练的模型（与论文表中 argmax 的 TF-IDF 结果一致，α = 1 可复现）。
- 流水线：阶段 1（v3.1 池上的 TF-IDF + LR）不使用任何 v4.0 标签，对 v3.1 指标的概率做同样的解码后再用规则 R 换算；
  α 在同一验证集上选。v3.1 的严重程度：AV N>A>L>P，AC L>H，PR N>L>H，UI N>R，S C>U，C/I/A H>L>N。
输出：results/review_checks/risk_baselines.md、risk_baselines.json（含每个 α 的测试集结果，可画权衡曲线）
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import CUTOFF, M31, M40, SEED, evaluate, load, source_type_map  # noqa: E402
from pilot_transfer import v31_pool  # noqa: E402
from risk_decode import ALPHAS, SEVERITY  # noqa: E402
from rq1_stats import rule_convert  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "review_checks"
SEV31 = {"AV": ["N", "A", "L", "P"], "AC": ["L", "H"], "PR": ["N", "L", "H"], "UI": ["N", "R"], "S": ["C", "U"],
         "C": ["H", "L", "N"], "I": ["H", "L", "N"], "A": ["H", "L", "N"]}
KEYS = ["mean_macro_f1", "band_acc", "under_rate", "hc_recall", "score_mae"]


def fit_probs(train_text, train_y, query_texts, metrics, min_df, max_feat):
    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=min_df, max_features=max_feat, sublinear_tf=True)
    x = vec.fit_transform(train_text)
    xq = [vec.transform(q) for q in query_texts]
    out = [dict() for _ in query_texts]
    for k in metrics:
        y = train_y[k]
        clf = LogisticRegression(C=4.0, max_iter=3000, random_state=SEED).fit(x, y)
        for i, q in enumerate(xq):
            out[i][k] = (list(clf.classes_), clf.predict_proba(q))
    return out


def decode(probs, alpha, sev):
    res = {}
    for k, (classes, p) in probs.items():
        ok = p >= alpha * p.max(1, keepdims=True)
        choice = np.full(len(p), -1)
        for c in reversed(sev[k]):
            if c in classes:
                choice = np.where(ok[:, classes.index(c)], classes.index(c), choice)
        res[k] = np.array(classes)[choice]
    return pd.DataFrame(res)


def to_v4(v31_df):
    return pd.DataFrame([rule_convert({k: r[k] for k in M31}) for _, r in v31_df.iterrows()])[M40]


def scan(val, test, pv, pt, sev, convert):
    rows = []
    for a in ALPHAS:
        row = {"alpha": a}
        for part, t, p in [("val", val, pv), ("test", test, pt)]:
            pred = decode(p, a, sev)
            pred = to_v4(pred) if convert else pred
            nd = (t["label_type"] != "derived").to_numpy()
            r = evaluate(t.reset_index(drop=True), pred)
            row |= {f"{part}_{k}": r[k] for k in KEYS}
            if part == "test" and nd.any():  # LOSO–VulDB 的测试集全是 derived，没有非 derived 子集
                r2 = evaluate(t[nd].reset_index(drop=True), pred[nd].reset_index(drop=True))
                row |= {f"test_nd_{k}": r2[k] for k in KEYS}
        rows.append(row)
    base = rows[0]["val_mean_macro_f1"]
    chosen = min([r for r in rows if r["val_mean_macro_f1"] >= base - 0.01], key=lambda r: (r["val_under_rate"], -r["val_mean_macro_f1"]))
    return {"chosen_alpha": chosen["alpha"], "argmax": rows[0], "chosen": chosen, "scan": rows}


SPLITS = ["temporal", "loso:VulnCheck", "loso:GitHub_M", "loso:VulDB"]


def part_path(split):
    return OUT / f"risk_baselines_{split.replace(':', '-')}.json"


def main():
    # 用法：python src/risk_decode_baselines.py [划分 ...]；每个划分的结果单独存盘（可分几个进程并行跑），最后汇总已有的全部划分
    todo = [] if sys.argv[1:] == ["--summary"] else (sys.argv[1:] or SPLITS)  # --summary：只汇总已存盘的划分
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    OUT.mkdir(parents=True, exist_ok=True)
    for split in todo:
        if split == "temporal":
            train, test = df[df["pub"] < CUTOFF], df[df["pub"] >= CUTOFF]
            pool = v31_pool(before_cutoff=True)
        else:
            s = split.split(":", 1)[1]
            train, test = df[df["source"] != s], df[df["source"] == s]
            pool = v31_pool(before_cutoff=False)
            pool = pool[pool["cna_short_name"].fillna("UNKNOWN") != s]
        train = train.sort_values("pub")
        n_fit = int(round(len(train) * 0.9))
        fit, val = train.iloc[:n_fit], train.iloc[n_fit:]
        test = test.reset_index(drop=True)
        print(f"== {split}: 训练 {len(train):,}（α 选择用前 {len(fit):,} 条）/ 验证 {len(val):,} / 测试 {len(test):,}", flush=True)
        ys = {k: train["y_" + k].values for k in M40}
        yfit = {k: fit["y_" + k].values for k in M40}
        (pv,) = fit_probs(fit["text"], yfit, [val["text"]], M40, 2, 200_000)
        (pt,) = fit_probs(train["text"], ys, [test["text"]], M40, 2, 200_000)
        res = {"tfidf": scan(val, test, pv, pt, SEVERITY, False)}
        print("  TF-IDF 完成，选定 α =", res["tfidf"]["chosen_alpha"], flush=True)
        pv31, pt31 = fit_probs(pool["text"], {k: pool["z_" + k].values for k in M31}, [val["text"], test["text"]], M31, 3, 300_000)
        res["pipeline_R"] = scan(val, test, pv31, pt31, SEV31, True)
        print("  流水线完成，选定 α =", res["pipeline_R"]["chosen_alpha"], flush=True)
        part_path(split).write_text(json.dumps(res, indent=1), encoding="utf-8")
    results = {s: json.loads(part_path(s).read_text(encoding="utf-8")) for s in SPLITS if part_path(s).exists()}
    lines = ["# TF-IDF 与流水线（规则 R）的风险敏感解码（测试集；α 在验证集上选）\n",
             "| 划分 | 方法 | 解码 | α | 平均宏 F1 | 等级准确率 | 低估率 | 高估率 | H+C 召回 | MAE |", "|---|---|---|---|---|---|---|---|---|---|"]
    for split, r in results.items():
        for m, x in r.items():
            for name, row in [("argmax", x["argmax"]), ("风险敏感", x["chosen"])]:
                over = 1 - row["test_band_acc"] - row["test_under_rate"]
                lines.append(f"| {split} | {m} | {name} | {row['alpha']:.1f} | {row['test_mean_macro_f1']:.3f} | {row['test_band_acc']:.3f} | "
                             f"{row['test_under_rate']:.3f} | {over:.3f} | {row['test_hc_recall']:.3f} | {row['test_score_mae']:.3f} |")
    lines += ["\n## 时间划分：各 α 下的测试集结果（权衡曲线）\n", "| 方法 | α | 平均宏 F1 | 等级准确率 | 低估率 | 高估率 | 非 derived 等级准确率 | 非 derived 低估率 |", "|---|---|---|---|---|---|---|---|"]
    for m, x in results.get("temporal", {}).items():
        for row in x["scan"]:
            lines.append(f"| {m} | {row['alpha']:.1f} | {row['test_mean_macro_f1']:.3f} | {row['test_band_acc']:.3f} | {row['test_under_rate']:.3f} | "
                         f"{1 - row['test_band_acc'] - row['test_under_rate']:.3f} | {row['test_nd_band_acc']:.3f} | {row['test_nd_under_rate']:.3f} |")
    (OUT / "risk_baselines.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
