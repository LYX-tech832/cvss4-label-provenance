"""复评后补的两项检查（10-07，CPU）。

A. TF-IDF 的设置是否影响"分类器与流水线的排名翻转"（时间划分，T2）。论文里 TF-IDF + LR 的 C = 4 和两套特征设置
   （分类器：最小文档频率 2、至多 20 万特征；流水线第一阶段：3、30 万）是一开始就定下的，没有调过。这里：
   - 分类器取 C ∈ {0.25, 1, 4, 16, 64, 256}（验证集上的最优值起初落在 16 这个边界上，所以向上扩了两档）：在验证集（训练数据里最新的 10%）上算平均宏 F1，再用全部训练标签重训、在测试集上评估；
   - 流水线第一阶段取 C ∈ {1, 4, 16}：在 v3.1 语料最新的 10% 上算 v3.1 的平均宏 F1，再用全部语料重训；
   - 两边交换特征设置各跑一次（C = 4）；
   - 大模型样本（2,000 条）上 DeepSeek-V4-Pro 与各个 C 的分类器的平均宏 F1 之差（论文 7.5 节的那处翻转）；
   - 报告各组合下"分类器 − 流水线"的等级准确率差（全部 / 非 derived），以及按各自验证集选出的组合的配对 bootstrap 区间。
   每个配置的预测缓存在 results/tfidf_sensitivity/，可以分多次跑完。约 1–1.5 小时。
B. 表 S14 的补充行：带辅助任务的模型只用种子 0–2 时的结果（表里原来是 5 个种子，而 Note S6 的差值是按 3 个种子算的）。几秒。
输出：results/review_checks/summary16.md
用法：python src/review_checks10.py [a|b|all]
"""

import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded, fast_scores  # noqa: E402
from baselines_v0 import CUTOFF, M31, M40, SEED, evaluate, load, source_type_map  # noqa: E402
from cvss_utils import V31_METRICS  # noqa: E402
from pilot_transfer import v31_pool  # noqa: E402
from pipeline_baseline import convert  # noqa: E402
from review_checks import clean_mask  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
CACHE = ROOT / "results" / "tfidf_sensitivity"
OUT = ROOT / "results" / "review_checks" / "summary16.md"
C_CLF, C_PIPE = [0.25, 1.0, 4.0, 16.0, 64.0, 256.0], [1.0, 4.0, 16.0]
F_CLF, F_PIPE = (2, 200_000), (3, 300_000)


def fit_predict(train_text, ys, queries, C, feat):
    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=feat[0], max_features=feat[1], sublinear_tf=True)
    x = vec.fit_transform(train_text)
    xq = [vec.transform(q) for q in queries]
    out = [{} for _ in queries]
    for k, y in ys.items():
        if len(set(y)) == 1:
            for o, q in zip(out, xq):
                o[k] = [y[0]] * q.shape[0]
            continue
        clf = LogisticRegression(C=C, max_iter=3000, random_state=SEED).fit(x, y)
        for o, q in zip(out, xq):
            o[k] = clf.predict(q)
    return [pd.DataFrame(o) for o in out]


def cached(name, fn):
    """fn() 返回 (测试集预测, 验证得分)；结果缓存。"""
    f, g = CACHE / f"{name}.parquet", CACHE / f"{name}.json"
    if f.exists() and g.exists():
        return pd.read_parquet(f), json.loads(g.read_text())["val"]
    t0 = time.time()
    pred, val = fn()
    pred.to_parquet(f, index=False)
    g.write_text(json.dumps({"val": val, "seconds": round(time.time() - t0)}))
    print(f"  {name}: 验证 {val}, 用时 {time.time() - t0:.0f} 秒", flush=True)
    return pred, val


def part_a(lines):
    CACHE.mkdir(parents=True, exist_ok=True)
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    train, test = df[df["pub"] < CUTOFF], df[df["pub"] >= CUTOFF].reset_index(drop=True)
    order = train.sort_values("pub", kind="stable")
    n_val = int(0.1 * len(order))
    fit, val = order.iloc[:-n_val], order.iloc[-n_val:].reset_index(drop=True)
    tv = Encoded(val, "y_")

    def clf(C, feat):
        def run():
            ys = lambda d: {k: d["y_" + k].values for k in M40}  # noqa: E731
            pv = fit_predict(fit["text"], ys(fit), [val["text"]], C, feat)[0]
            v = fast_scores(tv, Encoded(pv), np.arange(len(val)))["mean_macro_f1"]
            pt = fit_predict(train["text"], ys(train), [test["text"]], C, feat)[0]
            return pt.assign(cve_id=test["cve_id"].values), round(v, 4)
        return cached(f"clf_C{C}_df{feat[0]}", run)

    pool = v31_pool(before_cutoff=True)
    porder = pool.sort_values("pub", kind="stable")
    pn = int(0.1 * len(porder))
    pfit, pval = porder.iloc[:-pn], porder.iloc[-pn:]

    def pipe(C, feat):
        def run():
            ys = lambda d: {k: d["z_" + k].values for k in M31}  # noqa: E731
            pv = fit_predict(pfit["text"], ys(pfit), [pval["text"]], C, feat)[0]
            v = float(np.mean([f1_score(pval["z_" + k].values, pv[k].values, labels=V31_METRICS[k], average="macro", zero_division=0) for k in M31]))
            p31 = fit_predict(pool["text"], ys(pool), [test["text"]], C, feat)[0]
            return convert(p31, True).assign(cve_id=test["cve_id"].values), round(v, 4)
        return cached(f"pipe_C{C}_df{feat[0]}", run)

    print(f"A：分类器训练 {len(train):,}（验证 {n_val:,}），语料 {len(pool):,}（验证 {pn:,}），测试 {len(test):,}", flush=True)
    clfs = {C: clf(C, F_CLF) for C in C_CLF}
    clf_swap = clf(4.0, F_PIPE)
    pipes = {C: pipe(C, F_PIPE) for C in C_PIPE}
    pipe_swap = pipe(4.0, F_CLF)

    t = Encoded(test, "y_")
    alli, ndi = np.arange(len(test)), np.flatnonzero((test["label_type"] != "derived").to_numpy())
    enc = lambda p: Encoded(p.set_index("cve_id").loc[test["cve_id"]].reset_index())  # noqa: E731
    ec = {C: enc(p) for C, (p, _) in clfs.items()}
    ep = {C: enc(p) for C, (p, _) in pipes.items()}
    sc = lambda e: (fast_scores(t, e, alli), fast_scores(t, e, ndi))  # noqa: E731
    lines += ["## A. TF-IDF 的设置与排名翻转（时间划分；测试集 21,900 条，非 derived 16,749 条）\n",
              f"分类器在 {len(fit):,} 条上训练、{n_val:,} 条上验证后，用全部 {len(train):,} 条重训；流水线第一阶段在 v3.1 语料的 {len(pfit):,} 条上训练、{pn:,} 条上验证后，用全部 {len(pool):,} 条重训。\n",
              "### 分类器（TF-IDF + LR，v4.0 标签；最小文档频率 2，至多 20 万特征）\n",
              "| C | 验证集平均宏 F1 | 测试：平均宏 F1 全部 / 非 derived | 测试：等级准确率 全部 / 非 derived |", "|---|---|---|---|"]
    for C, (p, v) in clfs.items():
        a, b = sc(ec[C])
        lines.append(f"| {C:g}{'（论文）' if C == 4.0 else ''} | {v:.4f} | {a['mean_macro_f1']:.3f} / {b['mean_macro_f1']:.3f} | {a['band_acc']:.3f} / {b['band_acc']:.3f} |")
    lines += ["\n### 流水线（第一阶段 TF-IDF + LR 预测 v3.1，再用规则 R 换算；最小文档频率 3，至多 30 万特征）\n",
              "| C | 验证：v3.1 平均宏 F1 | 测试：平均宏 F1 全部 / 非 derived | 测试：等级准确率 全部 / 非 derived |", "|---|---|---|---|"]
    for C, (p, v) in pipes.items():
        a, b = sc(ep[C])
        lines.append(f"| {C:g}{'（论文）' if C == 4.0 else ''} | {v:.4f} | {a['mean_macro_f1']:.3f} / {b['mean_macro_f1']:.3f} | {a['band_acc']:.3f} / {b['band_acc']:.3f} |")
    lines += ["\n### 等级准确率之差：分类器 − 流水线，全部 / 非 derived\n", "| 分类器 C ＼ 流水线 C | " + " | ".join(f"{c:g}" for c in C_PIPE) + " |", "|---|" + "---|" * len(C_PIPE)]
    da, dn = [], []
    for cc in C_CLF:
        cells = []
        for cp in C_PIPE:
            a = (t.band == ec[cc].band).mean() - (t.band == ep[cp].band).mean()
            n = (t.band[ndi] == ec[cc].band[ndi]).mean() - (t.band[ndi] == ep[cp].band[ndi]).mean()
            da.append(a)
            dn.append(n)
            cells.append(f"{a:+.3f} / {n:+.3f}")
        lines.append(f"| {cc:g} | " + " | ".join(cells) + " |")
    lines.append(f"\n{len(da)} 个组合里：全部标签上的差在 {min(da):+.3f} 到 {max(da):+.3f} 之间，非 derived 上在 {min(dn):+.3f} 到 {max(dn):+.3f} 之间；"
                 f"全部标签上为正的 {sum(x > 0 for x in da)} 个，非 derived 上为负的 {sum(x < 0 for x in dn)} 个。")
    bc = max(clfs, key=lambda c: clfs[c][1])
    bp = max(pipes, key=lambda c: pipes[c][1])
    rng = np.random.default_rng(0)
    hit_c, hit_p = (t.band == ec[bc].band).astype(float), (t.band == ep[bp].band).astype(float)
    res = []
    for idx in (alli, ndi):
        d = hit_c[idx] - hit_p[idx]
        bs = [d[rng.integers(len(d), size=len(d))].mean() for _ in range(1000)]
        res.append(f"{d.mean():+.3f} [{np.percentile(bs, 2.5):+.3f}, {np.percentile(bs, 97.5):+.3f}]")
    lines.append(f"\n按各自验证集选出的设置（分类器 C = {bc:g}，流水线 C = {bp:g}）：等级准确率之差 全部 {res[0]}，非 derived {res[1]}（配对 bootstrap，1,000 次）。"
                 f"平均宏 F1 之差：全部 {sc(ec[bc])[0]['mean_macro_f1'] - sc(ep[bp])[0]['mean_macro_f1']:+.3f}，非 derived {sc(ec[bc])[1]['mean_macro_f1'] - sc(ep[bp])[1]['mean_macro_f1']:+.3f}。")
    llm = pd.read_parquet(ROOT / "results" / "autocvss_baseline" / "deepseek-v4-pro_DTD_s0" / "predictions.parquet")
    samp = df.set_index("cve_id").loc[llm["cve_id"]].reset_index()
    ts, el = Encoded(samp, "y_"), Encoded(llm)
    lt = samp["label_type"].to_numpy()
    strata = [np.flatnonzero(lt == x) for x in ["derived", "independent", "v4_only", "other"]]
    rng2 = np.random.default_rng(0)
    lines += ["\n### 大模型样本（2,000 条）：DeepSeek-V4-Pro − 分类器 的平均宏 F1（配对 bootstrap，按标签类型分层，1,000 次）\n",
              "| 分类器 C | 样本整体 | 非 derived（1,700） |", "|---|---|---|"]
    for C, (p, _) in clfs.items():
        es = Encoded(p.set_index("cve_id").loc[llm["cve_id"]].reset_index())

        def d(ix):
            nd = ix[lt[ix] != "derived"]
            return (fast_scores(ts, el, ix)["mean_macro_f1"] - fast_scores(ts, es, ix)["mean_macro_f1"],
                    fast_scores(ts, el, nd)["mean_macro_f1"] - fast_scores(ts, es, nd)["mean_macro_f1"])
        pt = d(np.arange(len(samp)))
        bs = np.array([d(np.concatenate([rng2.choice(x, size=len(x), replace=True) for x in strata])) for _ in range(1000)])
        lines.append(f"| {C:g}{'（论文）' if C == 4.0 else ''} | {pt[0]:+.3f} [{np.percentile(bs[:, 0], 2.5):+.3f}, {np.percentile(bs[:, 0], 97.5):+.3f}] | "
                     f"{pt[1]:+.3f} [{np.percentile(bs[:, 1], 2.5):+.3f}, {np.percentile(bs[:, 1], 97.5):+.3f}] |")
    lines += ["\n### 交换特征设置（C = 4）\n", "| 设置 | 测试：等级准确率 全部 / 非 derived | 分类器 − 流水线（全部 / 非 derived） |", "|---|---|---|"]
    es, ps = enc(clf_swap[0]), enc(pipe_swap[0])
    band = lambda e: ((t.band == e.band).mean(), (t.band[ndi] == e.band[ndi]).mean())  # noqa: E731
    for name, ce, pe in [("论文的设置（分类器 2 / 20 万，流水线 3 / 30 万）", ec[4.0], ep[4.0]), ("分类器改用 3 / 30 万", es, ep[4.0]), ("流水线改用 2 / 20 万", ec[4.0], ps), ("两边都交换", es, ps)]:
        (ca, cn), (pa, pn_) = band(ce), band(pe)
        lines.append(f"| {name} | 分类器 {ca:.3f} / {cn:.3f}；流水线 {pa:.3f} / {pn_:.3f} | {ca - pa:+.3f} / {cn - pn_:+.3f} |")


def part_b(lines):
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    clean = clean_mask(test).to_numpy() if hasattr(clean_mask(test), "to_numpy") else np.asarray(clean_mask(test))
    subsets = {"R-inc.": clean, "No v3.1": (~test["has_v31"]).to_numpy(), "R-inc., no VulnCheck": clean & (test["source"] != "VulnCheck").to_numpy()}
    atp = clean & (test["y_AT"] == "P").to_numpy()
    lines += ["\n## B. 表 S14 的补充行：带辅助任务的模型（5 轮），5 个种子与种子 0–2\n",
              "| 种子 | " + " | ".join(f"{k}（{int(m.sum()):,}）" for k, m in subsets.items()) + " | AT:P 预测为 None | AT 宏 F1（R-inc.） |", "|---|---|---|---|---|---|"]
    for name, seeds in [("0–4（表里原有的一行）", range(5)), ("0–2", range(3))]:
        ps = [pd.read_parquet(ENC / f"T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s{s}" / "pred_latent.parquet").set_index("cve_id").loc[test["cve_id"]].reset_index() for s in seeds]
        cells = []
        for m in subsets.values():
            idx = np.flatnonzero(m)
            rs = [evaluate(test.iloc[idx].reset_index(drop=True), p.iloc[idx].reset_index(drop=True)) for p in ps]
            cells.append(f"{np.mean([r['mean_macro_f1'] for r in rs]):.3f} / {np.mean([r['band_acc'] for r in rs]):.3f}")
        idx = np.flatnonzero(clean)
        at = np.mean([evaluate(test.iloc[idx].reset_index(drop=True), p.iloc[idx].reset_index(drop=True))["per_metric"]["AT"]["macro_f1"] for p in ps])
        share = np.mean([(p["AT"].to_numpy()[atp] == "N").mean() for p in ps])
        lines.append(f"| {name} | " + " | ".join(cells) + f" | {share:.3f} | {at:.3f} |")


def main():
    part = sys.argv[1] if len(sys.argv) > 1 else "all"
    lines = ["# TF-IDF 设置的敏感性；表 S14 的三种子行（自动生成）\n"]
    if part in ("a", "all"):
        part_a(lines)
    if part in ("b", "all"):
        part_b(lines)
    if part == "all":
        OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"已写入 {OUT}")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
