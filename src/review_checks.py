"""回应审稿意见（2026-09-29 两份模拟审稿）的核查（CPU，几分钟）。

① FD_oos 的稳健性：测试段里未见过的 v3.1 向量的比例（回退触发率）；三种回退方式（规则 R / 训练段最常见 v4 向量 / 不回退、只算见过的）
   下的 FD_oos 与 0.90 分型是否改变；Wilson 95% 区间。分别用全部数据与 2026 年前数据（分型窗口）。
② "最干净"子集：双版本评分且 v4.0 ≠ 规则 R(v3.1) 的 CVE。评测虚高（全部 / 非 derived / 干净子集）与排名翻转在该子集上是否成立。
③ AutoCVSS 后处理：DONT_KNOW 改填训练集最常见值后，DeepSeek 与 TF-IDF 的差值（按标签类型，类型内配对 bootstrap）。
④ CVSS v4.0 打分的单调性：把任一指标调严重一级，CVSS-B 分数与严重等级是否可能下降（穷举全部 104,976 个基础向量）。
⑤ v3.1 辅助池中 CNA 与 ADP 标签的比例。
⑥ 各划分内，5 个种子中有辅助版本胜出的个数。
⑦ 时间泄漏上限：发布于 2026 年前、但记录在 2026 年后更新过的 v4 训练样本与分型样本的比例（记录级更新时间，是上限）。
输出：results/review_checks/summary.md
"""

import itertools
import json
import sys
from collections import Counter, defaultdict
from math import sqrt
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded, fast_scores  # noqa: E402
from baselines_v0 import CUTOFF, M31, M40, evaluate, load, source_type_map, v4_score, SEVERITY_ORDER  # noqa: E402
from label_provenance import collect  # noqa: E402
from pilot_transfer import v31_pool  # noqa: E402
from rq1_stats import rule_convert  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "review_checks"
ENC = ROOT / "results" / "encoder"
LLM = ROOT / "results" / "autocvss_baseline" / "deepseek-v4-pro_DTD_s0"
PRED = ROOT / "results" / "baselines_v0" / "predictions"
ORDER = {"AV": "NALP", "AC": "LH", "AT": "NP", "PR": "NLH", "UI": "NPA", "VC": "HLN", "VI": "HLN", "VA": "HLN",
         "SC": "HLN", "SI": "HLN", "SA": "HLN"}  # 从最严重到最不严重（与风险敏感解码一致）


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (c - h, c + h)


def fd_variants(pairs):
    n = len(pairs)
    cut = int(0.7 * n)
    learn = defaultdict(Counter)
    for t31, _, t4, _ in pairs[:cut]:
        learn[t31][t4] += 1
    mapping = {k: c.most_common(1)[0][0] for k, c in learn.items()}
    majority = Counter(t4 for _, _, t4, _ in pairs[:cut]).most_common(1)[0][0]
    test = pairs[cut:]
    seen = [t31 in mapping for t31, _, _, _ in test]
    hit_r = [mapping.get(t31, tuple(rule_convert(d31)[k] for k in M40)) == t4 for t31, d31, t4, _ in test]
    hit_m = [mapping.get(t31, majority) == t4 for t31, _, t4, _ in test]
    hit_s = [mapping[t31] == t4 for t31, _, t4, _ in test if t31 in mapping]
    return {"n_test": len(test), "fallback": 1 - np.mean(seen), "fd_R": np.mean(hit_r), "ci": wilson(sum(hit_r), len(test)),
            "fd_maj": np.mean(hit_m), "fd_seen": np.mean(hit_s) if hit_s else float("nan")}


def part1(df, lines):
    lines += ["\n## ① FD_oos 的回退方式与置信区间\n",
              "回退 = 测试段（后 30%）里训练段没见过的 v3.1 向量所占比例。三种回退：规则 R（论文所用）/ 训练段最常见的 v4 向量 / 不回退（只算见过的）。",
              "区间为规则 R 回退下的 Wilson 95% 区间。\n"]
    for name, sub in [("全部数据", df), ("2026 年前（分型窗口）", df[df["pub"] < CUTOFF])]:
        pairs = collect(sub)
        lines += [f"\n### {name}\n", "| CNA | 对数 | 测试段 n | 回退触发率 | FD_oos（规则 R 回退） | 95% 区间 | FD_oos（最常见值回退） | FD_oos（只算见过的） | 0.90 分型是否随回退方式改变 |",
                  "|---|---|---|---|---|---|---|---|---|"]
        for s, p in sorted(pairs.items(), key=lambda x: -len(x[1])):
            if len(p) < 100:
                continue
            r = fd_variants(p)
            types = {v >= 0.90 for v in [r["fd_R"], r["fd_maj"]] + ([r["fd_seen"]] if not np.isnan(r["fd_seen"]) else [])}
            lines.append(f"| {s} | {len(p):,} | {r['n_test']} | {r['fallback']:.1%} | {r['fd_R']:.1%} | [{r['ci'][0]:.1%}, {r['ci'][1]:.1%}] | "
                         f"{r['fd_maj']:.1%} | {r['fd_seen']:.1%} | {'**是**' if len(types) > 1 else '否'} |")


def clean_mask(df):
    """双版本评分且 v4.0 向量 ≠ 规则 R(同来源 v3.1)。"""
    out = np.zeros(len(df), bool)
    for i, (_, r) in enumerate(df.iterrows()):
        if not r["has_v31"]:
            continue
        conv = rule_convert({k: r["x31_" + k] for k in M31})
        out[i] = any(conv[k] != r["y_" + k] for k in M40)
    return out


def scores(t, p):
    r = evaluate(t.reset_index(drop=True), p.reset_index(drop=True))
    return r["mean_macro_f1"], r["band_acc"]


def aligned(path, ids):
    return pd.read_parquet(path).set_index("cve_id").loc[ids].reset_index()


def part2_3(df, lines):
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    test["clean"] = clean_mask(test)
    tfidf = aligned(PRED / "T2_temporal_tfidf_lr.parquet", test["cve_id"])
    aux = [aligned(f, test["cve_id"]) for f in sorted(ENC.glob("T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s[0-9]/pred_latent.parquet"))]
    lines += ["\n## ② \"最干净\"子集：双版本评分且 v4.0 ≠ 规则 R(v3.1)\n",
              f"时间划分测试集：全部 {len(test):,}；非 derived {int((test['label_type'] != 'derived').sum()):,}；干净子集 {int(test['clean'].sum()):,}"
              f"（其中 derived 标签 {int((test['clean'] & (test['label_type'] == 'derived')).sum())} 条）。\n",
              "| 方法 | 口径 | n | 平均宏 F1 | 等级准确率 |", "|---|---|---|---|---|"]
    for scope, m in [("全部", np.ones(len(test), bool)), ("非 derived", (test["label_type"] != "derived").to_numpy()), ("干净子集", test["clean"].to_numpy())]:
        f, b = scores(test[m], tfidf[m])
        lines.append(f"| TF-IDF + LR | {scope} | {int(m.sum()):,} | {f:.3f} | {b:.3f} |")
        rs = [scores(test[m], p[m]) for p in aux]
        lines.append(f"| DeBERTa + v3.1 辅助（5 种子均值） | {scope} | {int(m.sum()):,} | {np.mean([r[0] for r in rs]):.3f} | {np.mean([r[1] for r in rs]):.3f} |")

    # LLM 样本
    llm = pd.read_parquet(LLM / "predictions.parquet")
    ids = llm["cve_id"]
    s = df.set_index("cve_id").loc[ids].reset_index()
    s["clean"] = clean_mask(s)
    raw = [json.loads(line) for line in (LLM / "raw.jsonl").read_text(encoding="utf-8").splitlines()]
    unknown = {(r["cve_id"], r["metric"]) for r in raw if r["label"] in (None, "DONT_KNOW")}
    train = df[df["pub"] < CUTOFF]
    majority = {k: train["y_" + k].mode()[0] for k in M40}
    alt = llm.set_index("cve_id").loc[ids].reset_index()
    pos = {c: i for i, c in enumerate(alt["cve_id"])}
    for cve, k in unknown:
        if cve in pos:
            alt.iloc[pos[cve], alt.columns.get_loc(k)] = majority[k]
    methods = {"DeepSeek（原做法）": llm.set_index("cve_id").loc[ids].reset_index(), "DeepSeek（DONT_KNOW→最常见值）": alt,
               "TF-IDF": aligned(PRED / "T2_temporal_tfidf_lr.parquet", ids)}
    t = Encoded(s, "y_")
    enc = {n: Encoded(p) for n, p in methods.items()}
    lt = s["label_type"].to_numpy()
    rng = np.random.default_rng(0)
    scopes = {"样本整体": ["derived", "independent", "v4_only", "other"], "去掉 derived": ["independent", "v4_only", "other"],
              "independent": ["independent"], "v4_only": ["v4_only"], "other": ["other"], "derived": ["derived"]}
    lines += ["\n## ③ AutoCVSS 后处理：DONT_KNOW → 训练集最常见值（同一批 2,000 条；类型内配对 bootstrap 1,000 次）\n",
              f"DONT_KNOW 或失败的（CVE, 指标）对：{len(unknown):,}（占 {len(unknown) / (len(ids) * 11):.1%}）。\n",
              "| 口径 | n | DeepSeek 原做法 宏F1 / 等级 | DeepSeek 最常见值 宏F1 / 等级 | TF-IDF 宏F1 / 等级 | (最常见值 − TF-IDF) 宏F1 差 [95%] | 等级准确率差 [95%] |",
              "|---|---|---|---|---|---|---|"]
    for name, types in scopes.items():
        strata = [np.flatnonzero(lt == ty) for ty in types]
        idx = np.concatenate(strata)
        pt = {n: fast_scores(t, e, idx) for n, e in enc.items()}
        diffs = []
        for _ in range(1000):
            b = np.concatenate([rng.choice(x, size=len(x), replace=True) for x in strata])
            a, c = fast_scores(t, enc["DeepSeek（DONT_KNOW→最常见值）"], b), fast_scores(t, enc["TF-IDF"], b)
            diffs.append((a["mean_macro_f1"] - c["mean_macro_f1"], a["band_acc"] - c["band_acc"]))
        d = np.array(diffs)
        cell = lambda n: f"{pt[n]['mean_macro_f1']:.3f} / {pt[n]['band_acc']:.3f}"  # noqa: E731
        df1 = pt["DeepSeek（DONT_KNOW→最常见值）"]["mean_macro_f1"] - pt["TF-IDF"]["mean_macro_f1"]
        db = pt["DeepSeek（DONT_KNOW→最常见值）"]["band_acc"] - pt["TF-IDF"]["band_acc"]
        lines.append(f"| {name} | {len(idx):,} | {cell('DeepSeek（原做法）')} | {cell('DeepSeek（DONT_KNOW→最常见值）')} | {cell('TF-IDF')} | "
                     f"{df1:+.3f} [{np.percentile(d[:, 0], 2.5):+.3f}, {np.percentile(d[:, 0], 97.5):+.3f}] | "
                     f"{db:+.3f} [{np.percentile(d[:, 1], 2.5):+.3f}, {np.percentile(d[:, 1], 97.5):+.3f}] |")
    # 干净子集上的 LLM 对比（原做法）
    m = s["clean"].to_numpy()
    idx = np.flatnonzero(m)
    diffs = []
    for _ in range(1000):
        b = rng.choice(idx, size=len(idx), replace=True)
        diffs.append(fast_scores(t, enc["DeepSeek（原做法）"], b)["mean_macro_f1"] - fast_scores(t, enc["TF-IDF"], b)["mean_macro_f1"])
    a, c = fast_scores(t, enc["DeepSeek（原做法）"], idx), fast_scores(t, enc["TF-IDF"], idx)
    lines.append(f"\n样本中的干净子集（n = {len(idx)}）：DeepSeek（原做法）宏 F1 {a['mean_macro_f1']:.3f} / 等级 {a['band_acc']:.3f}；"
                 f"TF-IDF {c['mean_macro_f1']:.3f} / {c['band_acc']:.3f}；宏 F1 差 {a['mean_macro_f1'] - c['mean_macro_f1']:+.3f} "
                 f"[{np.percentile(diffs, 2.5):+.3f}, {np.percentile(diffs, 97.5):+.3f}]。")


def part4(lines):
    vals = [ORDER[k] for k in M40]
    viol_score, viol_band, total = Counter(), Counter(), 0
    for combo in itertools.product(*vals):
        vec = dict(zip(M40, combo))
        s0, b0 = v4_score("CVSS:4.0/" + "/".join(f"{k}:{vec[k]}" for k in M40))
        for k in M40:
            i = ORDER[k].index(vec[k])
            if i == 0:
                continue
            up = dict(vec, **{k: ORDER[k][i - 1]})
            s1, b1 = v4_score("CVSS:4.0/" + "/".join(f"{m}:{up[m]}" for m in M40))
            total += 1
            if s1 < s0 - 1e-9:
                viol_score[k] += 1
            if SEVERITY_ORDER.get(b1, -1) < SEVERITY_ORDER.get(b0, -1):
                viol_band[k] += 1
    lines += ["\n## ④ CVSS v4.0 打分的单调性（穷举全部基础向量，逐指标调严重一级）\n",
              f"检查的（向量, 指标）组合：{total:,}；分数下降的：{sum(viol_score.values()):,}（按指标：{dict(viol_score) or '无'}）；"
              f"严重等级下降的：{sum(viol_band.values()):,}（按指标：{dict(viol_band) or '无'}）。"]


def part5(lines):
    pool = v31_pool(before_cutoff=True)
    cna = pool["cna_v31"].map(len) > 0
    lines += ["\n## ⑤ v3.1 辅助池的标签来源（2026 年前）\n",
              f"共 {len(pool):,} 条：来自 CNA 容器 {int(cna.sum()):,}（{cna.mean():.1%}），来自 ADP 容器 {int((~cna).sum()):,}（{(~cna).mean():.1%}）。"]


def part6(lines):
    lines += ["\n## ⑥ 各划分内有辅助版本胜出的种子数（平均宏 F1，全部测试集）\n", "| 划分 | 胜出种子数 / 5 | 各种子差值 |", "|---|---|---|"]
    for split in ["temporal", "loso-VulnCheck", "loso-GitHub_M", "loso-VulDB"]:
        d = []
        for s in range(5):
            a = ENC / f"T2_{split}_deberta-v3-base_none_aux_e5_cwinv_sqrt_s{s}" / "results.json"
            b = ENC / f"T2_{split}_deberta-v3-base_none_e5_cwinv_sqrt_s{s}" / "results.json"
            if a.exists() and b.exists():
                d.append(json.loads(a.read_text(encoding="utf-8"))["latent"]["mean_macro_f1"] - json.loads(b.read_text(encoding="utf-8"))["latent"]["mean_macro_f1"])
        lines.append(f"| {split} | {sum(x > 0 for x in d)} / {len(d)} | " + ", ".join(f"{x:+.3f}" for x in d) + " |")


def part7(df, lines):
    upd = pd.to_datetime(df["date_updated"], utc=True, errors="coerce")
    pre = df["pub"] < CUTOFF
    late = upd >= CUTOFF
    dual = df["has_v31"]
    lines += ["\n## ⑦ 时间泄漏的上限（记录级更新时间；记录更新不一定是 v4.0 向量的改动，所以是上限）\n",
              f"- 2026 年前发布的 v4 样本（时间划分的训练 + 验证部分）：{int(pre.sum()):,} 条，其中记录在 2026 年后更新过的 {int((pre & late).sum()):,} 条（{(pre & late).sum() / pre.sum():.1%}）；",
              f"- 其中双版本评分（分型所用）的：{int((pre & dual).sum()):,} 条，2026 年后更新过的 {int((pre & dual & late).sum()):,} 条（{(pre & dual & late).sum() / (pre & dual).sum():.1%}）；",
              "- 按来源（2026 年后更新过的比例，训练部分 v4 样本数 ≥ 500 的来源）：" + "；".join(
                  f"{s} {g:.1%}" for s, g in df[pre].assign(late=late[pre]).groupby("source")["late"].agg(["mean", "size"]).query("size >= 500")["mean"].sort_values(ascending=False).items())]


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    lines = ["# 审稿意见核查（2026-09-29，自动生成）\n"]
    part1(df, lines)
    part2_3(df, lines)
    part4(lines)
    part5(lines)
    part6(lines)
    part7(df, lines)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
