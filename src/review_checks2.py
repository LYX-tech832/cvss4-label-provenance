"""回应审稿意见的第二批核查（CPU，约 10–20 分钟）。

A. 辅助任务增益的未取整差值，以及把训练随机性算进去的两种区间：
   种子层面的 t 区间（按种子号配对）；CVE 与种子一起重抽样的两层 bootstrap（每次对两个版本各自有放回地抽 5 个种子）。
B. 大模型对比按测试集真实构成加权（每次 bootstrap 按真实比例从各类型里抽 2,000 条）。
C. 逐指标的"虚高"：全部 vs 非 derived vs 干净子集（双版本评分且 v4 ≠ 规则 R(v3.1)）的宏 F1。
D. 近似重复：测试描述与训练描述（v4 训练集、v3.1 池）的 TF-IDF 余弦相似度最大值；VulDB 描述里的自带严重度措辞。
E. CNA 容器的更新时间（比记录级更新时间更接近"v4 向量何时写入"）：2026 年前发布、CNA 容器在 2026 年后更新的比例；
   去掉这些 CVE 后分型是否改变；TF-IDF 基线去掉这些训练样本后测试结果变化多少。
F. 合成换算约定：把 v4 标签换成"不是规则 R、但同样确定"的换算，看规则 R 一致率与 FD_oos 各给出多少。
输出：results/review_checks/summary2.md
"""

import json
import re
import sys
import zipfile
from collections import Counter
from pathlib import Path

import numpy as np
import orjson
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded, fast_scores  # noqa: E402
from baselines_v0 import CUTOFF, M31, M40, evaluate, load, pred_tfidf_lr, source_type_map  # noqa: E402
from label_provenance import THRESHOLD, analyse, collect  # noqa: E402
from pilot_transfer import v31_pool  # noqa: E402
from review_checks import clean_mask, fd_variants  # noqa: E402
from rq1_stats import rule_convert  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "review_checks"
ENC = ROOT / "results" / "encoder"
LLM = ROOT / "results" / "autocvss_baseline" / "deepseek-v4-pro_DTD_s0"
PRED = ROOT / "results" / "baselines_v0" / "predictions"
SPLITS = ["temporal", "loso-VulnCheck", "loso-GitHub_M", "loso-VulDB"]
T4 = 2.776  # t 分布 0.975 分位，自由度 4


def runs(split, aux):
    return [ENC / f"T2_{split}_deberta-v3-base_none{'_aux' if aux else ''}_e5_cwinv_sqrt_s{s}" for s in range(5)]


def enc_preds(dirs, ids):
    return [Encoded(pd.read_parquet(d / "pred_latent.parquet").set_index("cve_id").loc[ids].reset_index()) for d in dirs]


def part_a(df, lines, rng):
    lines += ["\n## A. 辅助任务增益：未取整差值与包含训练随机性的区间（平均宏 F1）\n",
              "| 划分 | 口径 | 差值（未取整） | 各种子差值 | 种子 t 区间（配对，df=4） | 两层 bootstrap 区间（CVE × 种子） |", "|---|---|---|---|---|---|"]
    for split in SPLITS:
        ids = pd.read_parquet(runs(split, False)[0] / "pred_latent.parquet")["cve_id"]
        truth = df.set_index("cve_id").loc[ids].reset_index()
        t = Encoded(truth, "y_")
        pn, pa = enc_preds(runs(split, False), ids), enc_preds(runs(split, True), ids)
        scopes = [("全部", np.arange(len(truth)))]
        if split == "temporal":
            scopes.append(("非 derived", np.flatnonzero(truth["label_type"].to_numpy() != "derived")))
        for name, pool in scopes:
            fa = np.array([fast_scores(t, p, pool)["mean_macro_f1"] for p in pa])
            fn = np.array([fast_scores(t, p, pool)["mean_macro_f1"] for p in pn])
            d = fa - fn
            m, sd = d.mean(), d.std(ddof=1)
            boots = []
            for _ in range(1000):
                idx = rng.choice(pool, size=len(pool), replace=True)
                sa, sn = rng.integers(0, 5, 5), rng.integers(0, 5, 5)
                boots.append(np.mean([fast_scores(t, pa[i], idx)["mean_macro_f1"] for i in sa]) -
                             np.mean([fast_scores(t, pn[i], idx)["mean_macro_f1"] for i in sn]))
            lo, hi = np.percentile(boots, [2.5, 97.5])
            lines.append(f"| {split} | {name} | {m:+.4f} | " + ", ".join(f"{x:+.3f}" for x in d) +
                         f" | [{m - T4 * sd / np.sqrt(5):+.3f}, {m + T4 * sd / np.sqrt(5):+.3f}] | [{lo:+.3f}, {hi:+.3f}] |")


def part_b(df, lines, rng):
    llm = pd.read_parquet(LLM / "predictions.parquet")
    ids = llm["cve_id"]
    s = df.set_index("cve_id").loc[ids].reset_index()
    raw = [json.loads(x) for x in (LLM / "raw.jsonl").read_text(encoding="utf-8").splitlines()]
    unknown = {(r["cve_id"], r["metric"]) for r in raw if r["label"] in (None, "DONT_KNOW")}
    train = df[df["pub"] < CUTOFF]
    alt = llm.set_index("cve_id").loc[ids].reset_index()
    pos = {c: i for i, c in enumerate(alt["cve_id"])}
    for cve, k in unknown:
        alt.iloc[pos[cve], alt.columns.get_loc(k)] = train["y_" + k].mode()[0]
    t = Encoded(s, "y_")
    meth = {"DeepSeek（原做法）": [Encoded(llm.set_index("cve_id").loc[ids].reset_index())],
            "DeepSeek（DONT_KNOW→最常见值）": [Encoded(alt)],
            "TF-IDF": [Encoded(pd.read_parquet(PRED / "T2_temporal_tfidf_lr.parquet").set_index("cve_id").loc[ids].reset_index())],
            "DeBERTa + 辅助": enc_preds(runs("temporal", True), ids)}
    test = df[df["pub"] >= CUTOFF]
    comp = test["label_type"].value_counts()
    lt = s["label_type"].to_numpy()
    lines += ["\n## B. 大模型对比按测试集真实构成加权（每次 bootstrap 从各类型按真实比例共抽 2,000 条，1,000 次；报告均值与 95% 区间）\n",
              "测试集构成：" + "，".join(f"{k} {v:,}（{v / len(test):.1%}）" for k, v in comp.items()) + "\n",
              "| 口径 | 方法 | 平均宏 F1 | 等级准确率 | 相对 TF-IDF 的宏 F1 差 | 等级准确率差 |", "|---|---|---|---|---|---|"]
    for scope, types in [("加权整体", ["derived", "independent", "v4_only", "other"]), ("加权非 derived", ["independent", "v4_only", "other"])]:
        w = comp[types] / comp[types].sum()
        sizes = {ty: int(round(2000 * w[ty])) for ty in types}
        strata = {ty: np.flatnonzero(lt == ty) for ty in types}
        res = {n: [] for n in meth}
        for _ in range(1000):
            b = np.concatenate([rng.choice(strata[ty], size=sizes[ty], replace=True) for ty in types])
            for n, ps in meth.items():
                sc = [fast_scores(t, p, b) for p in ps]
                res[n].append((np.mean([x["mean_macro_f1"] for x in sc]), np.mean([x["band_acc"] for x in sc])))
        base = np.array(res["TF-IDF"])
        for n in meth:
            a = np.array(res[n])
            d = a - base
            cell = "—" if n == "TF-IDF" else (f"{d[:, 0].mean():+.3f} [{np.percentile(d[:, 0], 2.5):+.3f}, {np.percentile(d[:, 0], 97.5):+.3f}] | "
                                              f"{d[:, 1].mean():+.3f} [{np.percentile(d[:, 1], 2.5):+.3f}, {np.percentile(d[:, 1], 97.5):+.3f}]")
            lines.append(f"| {scope} | {n} | {a[:, 0].mean():.3f} | {a[:, 1].mean():.3f} | {cell if n != 'TF-IDF' else '— | —'} |")


def per_metric(t, p):
    r = evaluate(t.reset_index(drop=True), p.reset_index(drop=True))
    return {k: r["per_metric"][k]["macro_f1"] for k in M40}


def part_c(test, lines):
    tf = pd.read_parquet(PRED / "T2_temporal_tfidf_lr.parquet").set_index("cve_id").loc[test["cve_id"]].reset_index()
    maj = pd.read_parquet(PRED / "T2_temporal_majority.parquet").set_index("cve_id").loc[test["cve_id"]].reset_index()
    ds = {v: [pd.read_parquet(d / "pred_latent.parquet").set_index("cve_id").loc[test["cve_id"]].reset_index() for d in runs("temporal", v)]
          for v in (False, True)}
    masks = {"全部": np.ones(len(test), bool), "非 derived": (test["label_type"] != "derived").to_numpy(), "干净子集": test["clean"].to_numpy()}
    lines += ["\n## C. 逐指标宏 F1（时间划分测试集；DeBERTa 为 5 种子均值）\n",
              "| 指标 | 多数类 全部 / 非 derived | TF-IDF 全部 / 非 derived / 干净 | DeBERTa 全部 / 非 derived | DeBERTa+辅助 全部 / 非 derived / 干净 | TF-IDF 虚高（全部 − 非 derived） | DeBERTa+辅助 虚高 |",
              "|---|---|---|---|---|---|---|"]
    res = {}
    for name, m in masks.items():
        tt = test[m]
        res[("maj", name)] = per_metric(tt, maj[m])
        res[("tf", name)] = per_metric(tt, tf[m])
        for v in (False, True):
            pm = [per_metric(tt, p[m]) for p in ds[v]]
            res[(v, name)] = {k: np.mean([x[k] for x in pm]) for k in M40}
    for k in M40:
        lines.append(f"| {k} | {res[('maj', '全部')][k]:.3f} / {res[('maj', '非 derived')][k]:.3f} | "
                     f"{res[('tf', '全部')][k]:.3f} / {res[('tf', '非 derived')][k]:.3f} / {res[('tf', '干净子集')][k]:.3f} | "
                     f"{res[(False, '全部')][k]:.3f} / {res[(False, '非 derived')][k]:.3f} | "
                     f"{res[(True, '全部')][k]:.3f} / {res[(True, '非 derived')][k]:.3f} / {res[(True, '干净子集')][k]:.3f} | "
                     f"{res[('tf', '全部')][k] - res[('tf', '非 derived')][k]:+.3f} | {res[(True, '全部')][k] - res[(True, '非 derived')][k]:+.3f} |")
    return tf, ds


def max_sim(query, refs, chunk=500):
    vec = TfidfVectorizer(ngram_range=(1, 1), min_df=2, sublinear_tf=True).fit(list(refs) + list(query))
    r, q = vec.transform(refs).T.tocsc(), vec.transform(query)
    out = np.zeros(q.shape[0])
    for i in range(0, q.shape[0], chunk):
        out[i:i + chunk] = (q[i:i + chunk] @ r).max(axis=1).toarray().ravel()
    return out


def part_d(df, test, tf, ds, lines):
    train = df[df["pub"] < CUTOFF]
    pool = v31_pool(before_cutoff=True)
    s_tr = max_sim(test["description"].str.strip(), train["description"].str.strip())
    s_pool = max_sim(test["description"].str.strip(), pool["description"].str.strip())
    lines += ["\n## D. 近似重复（TF-IDF 词项余弦相似度的最大值；≥ 0.9 视为近似重复）\n",
              "| 标签类型 | n | 与 v4 训练描述近似重复 | 与 v3.1 池近似重复 | 相似度中位数（v4 训练） |", "|---|---|---|---|---|"]
    for ty in ["derived", "independent", "v4_only", "other"]:
        m = (test["label_type"] == ty).to_numpy()
        lines.append(f"| {ty} | {m.sum():,} | {(s_tr[m] >= 0.9).mean():.1%} | {(s_pool[m] >= 0.9).mean():.1%} | {np.median(s_tr[m]):.2f} |")
    nd = s_tr < 0.9
    lines.append("\n去掉与 v4 训练描述近似重复的测试 CVE 后（等级准确率；DeBERTa+辅助为 5 种子均值）：")
    for name, m in [("derived", (test["label_type"] == "derived").to_numpy()), ("非 derived", (test["label_type"] != "derived").to_numpy())]:
        for sub, mm in [("全部", m), ("去掉近似重复", m & nd)]:
            b_tf = evaluate(test[mm].reset_index(drop=True), tf[mm].reset_index(drop=True))["band_acc"]
            b_ds = np.mean([evaluate(test[mm].reset_index(drop=True), p[mm].reset_index(drop=True))["band_acc"] for p in ds[True]])
            lines.append(f"- {name}，{sub}（n = {mm.sum():,}）：TF-IDF {b_tf:.3f}，DeBERTa+辅助 {b_ds:.3f}")
    vul = df[df["source"] == "VulDB"]
    cls = vul["description"].str.extract(r"(?:classified|rated) as (critical|problematic|very critical|uncritical)", flags=re.I)[0].str.lower()
    lines.append(f"\nVulDB 描述中含 \"classified/rated as <等级>\" 的：{cls.notna().mean():.1%}（{int(cls.notna().sum()):,} / {len(vul):,}）；各措辞与 v4.0 严重等级的交叉表（VulDB 全部 v4 标签）：\n")
    band = vul.apply(lambda r: __import__("baselines_v0").v4_score("CVSS:4.0/" + "/".join(f"{k}:{r['y_' + k]}" for k in M40))[1], axis=1)
    ct = pd.crosstab(cls.fillna("（无）"), band)
    lines.append("| 措辞 | " + " | ".join(ct.columns) + " |")
    lines.append("|---|" + "---|" * len(ct.columns))
    for w, row in ct.iterrows():
        lines.append(f"| {w} | " + " | ".join(f"{v:,}" for v in row) + " |")
    other = df[df["source"] != "VulDB"]["description"].str.contains(r"classified as (?:critical|problematic)", case=False).mean()
    lines.append(f"\n其他来源的描述中出现同样措辞的比例：{other:.2%}")


def cna_updated(ids):
    want = set(ids)
    out = {}
    with zipfile.ZipFile(ROOT / "data" / "raw" / "cves.zip") as z:
        for n in z.namelist():
            base = n.rsplit("/", 1)[-1][:-5] if n.endswith(".json") else None
            if base in want:
                rec = orjson.loads(z.read(n))
                out[base] = ((rec.get("containers") or {}).get("cna") or {}).get("providerMetadata", {}).get("dateUpdated")
    return pd.Series(out)


def part_e(df, lines):
    upd = pd.to_datetime(cna_updated(df["cve_id"]), utc=True, errors="coerce", format="mixed")
    df = df.assign(cna_upd=df["cve_id"].map(upd))
    pre = df["pub"] < CUTOFF
    late = df["cna_upd"] >= CUTOFF
    lines += ["\n## E. CNA 容器的更新时间（providerMetadata.dateUpdated；CNA 改动其容器任何内容都会更新它，所以仍是上限）\n",
              f"- 缺少 CNA 容器更新时间的：{int(df['cna_upd'].isna().sum())} 条；",
              f"- 2026 年前发布的 v4 样本 {int(pre.sum()):,} 条中，CNA 容器在 2026 年后更新过的 {int((pre & late).sum()):,} 条（{(pre & late).sum() / pre.sum():.1%}）；",
              f"- 其中双版本评分的 {int((pre & df['has_v31']).sum()):,} 条中 {int((pre & late & df['has_v31']).sum()):,} 条（{(pre & late & df['has_v31']).sum() / (pre & df['has_v31']).sum():.1%}）；",
              "- 按来源（训练部分 v4 样本 ≥ 500）：" + "；".join(
                  f"{s} {g['mean']:.1%}（{int(g['size']):,} 条）" for s, g in df[pre].assign(late=late[pre]).groupby("source")["late"].agg(["mean", "size"]).query("size >= 500").sort_values("mean", ascending=False).iterrows())]
    # 分型：去掉可能在 2026 年后才写入 v4 的 CVE
    keep = df[pre & ~late]
    pairs = collect(keep)
    old = json.loads((ROOT / "results" / "label_provenance" / "source_types.json").read_text(encoding="utf-8"))
    lines.append("\n去掉这些 CVE 后重新分型（2026 年前、双版本评分 ≥ 100 的来源）：")
    for s, p in sorted(pairs.items(), key=lambda x: -len(x[1])):
        if len(p) >= 100:
            fd = analyse(p)["FD_oos"]
            new_t = "derived" if fd >= THRESHOLD else "independent"
            lines.append(f"- {s}：{len(p):,} 对，FD_oos {fd:.1%} → {new_t}（原分型 {old.get(s, {}).get('type', '无')}，原 FD_oos {old.get(s, {}).get('FD_oos_pre2026', float('nan')):.1%}）")
    # TF-IDF 基线：去掉这些训练样本后重训
    test = df[df["pub"] >= CUTOFF]
    lines.append("\nTF-IDF 基线去掉这些训练样本后重训（测试集不变）：")
    for name, tr in [("原训练集", df[pre]), ("去掉 CNA 容器 2026 年后更新的", df[pre & ~late])]:
        pred = pred_tfidf_lr(tr, test, with_v31=False)
        for scope, m in [("全部", np.ones(len(test), bool)), ("非 derived", (test["label_type"] != "derived").to_numpy())]:
            r = evaluate(test[m].reset_index(drop=True), pred[m].reset_index(drop=True))
            lines.append(f"- {name}（训练 {len(tr):,} 条），{scope}：平均宏 F1 {r['mean_macro_f1']:.3f}，等级准确率 {r['band_acc']:.3f}，低估率 {r['under_rate']:.3f}")


def alt_convention(d31):
    """一个"不是规则 R、但同样确定"的换算约定：把攻击复杂度挪到 AT，UI:R → A，后续系统影响一律为 N。"""
    v = rule_convert(d31)
    v.update({"AC": "L", "AT": "P" if d31["AC"] == "H" else "N", "UI": "N" if d31["UI"] == "N" else "A", "SC": "N", "SI": "N", "SA": "N"})
    return tuple(v[k] for k in M40)


def part_f(df, lines):
    pairs = collect(df[df["pub"] < CUTOFF])
    lines += ["\n## F. 合成换算约定（2026 年前的数据；把每个来源的 v4 标签换成确定的非规则 R 换算后再做检验）\n",
              "| CNA | 对数 | 规则 R 一致率 | FD_oos（规则 R 回退） | FD_oos（只算见过的） | 回退触发率 | 是否被判为 derived |", "|---|---|---|---|---|---|---|"]
    for s, p in sorted(pairs.items(), key=lambda x: -len(x[1])):
        if len(p) < 100:
            continue
        syn = [(t31, d31, alt_convention(d31), None) for t31, d31, _, _ in p]
        agree = np.mean([tuple(rule_convert(d31)[k] for k in M40) == t4 for _, d31, t4, _ in syn])
        r = fd_variants(syn)
        lines.append(f"| {s} | {len(p):,} | {agree:.1%} | {r['fd_R']:.1%} | {r['fd_seen']:.1%} | {r['fallback']:.1%} | {'是' if r['fd_R'] >= THRESHOLD else '否'} |")


def main():
    rng = np.random.default_rng(0)
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    test["clean"] = clean_mask(test)
    lines = ["# 审稿意见核查（第二批，自动生成）\n"]
    for step in [lambda: part_a(df, lines, rng), lambda: part_b(df, lines, rng)]:
        step()
        print("\n".join(lines[-12:]), flush=True)
    tf, ds = part_c(test, lines)
    part_d(df, test, tf, ds, lines)
    print("\n".join(lines[-30:]), flush=True)
    part_e(df, lines)
    part_f(df, lines)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "summary2.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
