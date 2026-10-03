"""第六份审稿意见（SCI审稿报告.md，10-01）第二类分析（CPU，约 20 分钟）。

A（M1）函数依赖检验的校准：每个可检验来源（2026 年前、双版本评分 ≥ 100）的
   观察值 FD_oos、"总猜训练段最常见 v4 向量"的基线、来源内打乱 v3.1/v4 配对的置换零分布（200 次）；
   检出力模拟：把标签换成确定的非规则 R 换算（同 review_checks2 的合成约定），再以概率 p 随机替换为该来源的经验分布，
   看 FD_oos ≥ 0.90 的比例（50 次）；另用 VulDB 与 VulnCheck 的 v3.1 向量按样本量 n 抽样，看检出率随样本量的变化。
B（M3）来源特征：标签多样性（不同向量数、归一化熵、最常见向量占比）、描述长度、CWE 多样性；
   时间划分测试集中各中等以上来源（≥ 200 条）的结果。
C（M7）按厂商分簇的重抽样（厂商取 CNA 容器 affected 的第一个 vendor；缺失时每个 CVE 自成一簇），与按 CVE 重抽样的区间对比；
   另一种宏 F1（只在真值或预测中出现的取值上平均，即 scikit-learn 的默认做法）下的主要比较与排名翻转。
D（M10）风险敏感解码的决策指标（时间划分测试集）：High/Critical 精确率、升级比例（预测为 High/Critical 的比例）、
   跨两档及以上的严重错误；不同"低估代价 / 高估代价"比下的期望代价。
输出：results/review_checks/summary6.md
"""

import json
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import orjson
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded, fast_scores  # noqa: E402
from baselines_v0 import CUTOFF, M31, M40, SEVERITY_ORDER, load, source_type_map, to_vector, v4_score  # noqa: E402
from cvss_utils import V40_METRICS  # noqa: E402
from label_provenance import collect  # noqa: E402
from review_checks import fd_variants  # noqa: E402
from review_checks2 import alt_convention  # noqa: E402
from risk_decode import ALPHAS, decode  # noqa: E402
from rq1_stats import rule_convert  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
PRED = ROOT / "results" / "baselines_v0" / "predictions"
LLM = ROOT / "results" / "autocvss_baseline" / "deepseek-v4-pro_DTD_s0"
OUT = ROOT / "results" / "review_checks" / "summary6.md"
rng = np.random.default_rng(0)


# ---------------- A ----------------
def fd_oos_only(pairs):
    return fd_variants(pairs)["fd_R"]


def majority_baseline(pairs):
    cut = int(0.7 * len(pairs))
    top = Counter(t4 for _, _, t4, _ in pairs[:cut]).most_common(1)[0][0]
    return np.mean([t4 == top for _, _, t4, _ in pairs[cut:]])


def permuted(pairs):
    v4 = [p[2] for p in pairs]
    perm = rng.permutation(len(v4))
    return [(p[0], p[1], v4[j], None) for p, j in zip(pairs, perm)]


def noisy_synthetic(pairs, p):
    pool = [x[2] for x in pairs]
    out = []
    for t31, d31, _, _ in pairs:
        t4 = alt_convention(d31)
        if rng.random() < p:
            t4 = pool[rng.integers(len(pool))]
        out.append((t31, d31, t4, None))
    return out


def part_a(df, lines):
    pairs = {s: p for s, p in collect(df[df["pub"] < CUTOFF]).items() if len(p) >= 100}
    lines += ["## A. 函数依赖检验的校准（2026 年前、双版本评分 ≥ 100 的来源）\n",
              "| 来源 | 对数 | FD_oos（观察） | 最常见向量基线 | 置换零分布 均值 / 95% 分位 | 合成换算 + 噪声 p=0 / 0.05 / 0.10 / 0.20 时的检出率（50 次） |", "|---|---|---|---|---|---|"]
    for s, p in sorted(pairs.items(), key=lambda x: -len(x[1])):
        null = [fd_oos_only(permuted(p)) for _ in range(200)]
        det = []
        for noise in (0.0, 0.05, 0.10, 0.20):
            det.append(np.mean([fd_oos_only(noisy_synthetic(p, noise)) >= 0.90 for _ in range(50)]))
        lines.append(f"| {s} | {len(p):,} | {fd_oos_only(p):.3f} | {majority_baseline(p):.3f} | {np.mean(null):.3f} / {np.percentile(null, 95):.3f} | "
                     + " / ".join(f"{x:.2f}" for x in det) + " |")
    lines += ["\n检出率随样本量的变化（合成换算、无噪声；从该来源 2026 年前的双版本评分里按时间顺序取前 n 条；50 次随机子样本取平均时按随机抽样保持时间顺序）\n",
              "| v3.1 向量来自 | n=100 | n=200 | n=500 | n=1,000 | n=2,000 |", "|---|---|---|---|---|---|"]
    for s in ["VulDB", "VulnCheck", "siemens", "intel"]:
        if s not in pairs:
            continue
        p = pairs[s]
        cells = []
        for n in (100, 200, 500, 1000, 2000):
            if n > len(p):
                cells.append("—")
                continue
            hits = []
            for _ in range(50):
                idx = np.sort(rng.choice(len(p), size=n, replace=False))
                hits.append(fd_oos_only(noisy_synthetic([p[i] for i in idx], 0.0)) >= 0.90)
            cells.append(f"{np.mean(hits):.2f}")
        lines.append(f"| {s}（共 {len(p):,}） | " + " | ".join(cells) + " |")


# ---------------- B ----------------
def entropy(counts):
    c = np.array(list(counts.values()), dtype=float)
    q = c / c.sum()
    h = -(q * np.log2(q)).sum()
    return h / np.log2(len(c)) if len(c) > 1 else 0.0


def part_b(df, test, preds, lines):
    df = df.assign(vec=df[["y_" + k for k in M40]].astype(str).agg("/".join, axis=1),
                   dlen=df["description"].str.split().str.len(),
                   cwe=[(list(a) + list(b))[0] if len(a) + len(b) else None for a, b in zip(df["cwe_cna"], df["cwe_adp"])])
    groups = [("VulDB（derived）", df["source"] == "VulDB"), ("VulnCheck", df["source"] == "VulnCheck"), ("GitHub_M（v4-only）", df["source"] == "GitHub_M"),
              ("其他 independent 来源", (df["label_type"] == "independent") & (df["source"] != "VulnCheck")),
              ("其他 v4-only 来源", (df["label_type"] == "v4_only") & (df["source"] != "GitHub_M")), ("other", df["label_type"] == "other")]
    lines += ["\n## B. 来源特征（全部 v4.0 标签）\n",
              "| 来源 | n | 不同 v4 向量数 | 向量分布归一化熵 | 最常见向量占比 | 描述词数中位数 | 有 CWE 的比例 | 不同 CWE 数 | 前 3 个 CWE 占比 |", "|---|---|---|---|---|---|---|---|---|"]
    for name, m in groups:
        g = df[m]
        vc = Counter(g["vec"])
        cw = g["cwe"].dropna()
        top3 = sum(c for _, c in Counter(cw).most_common(3)) / len(cw) if len(cw) else float("nan")
        lines.append(f"| {name} | {len(g):,} | {len(vc):,} | {entropy(vc):.2f} | {vc.most_common(1)[0][1] / len(g):.1%} | {int(g['dlen'].median())} | "
                     f"{len(cw) / len(g):.1%} | {cw.nunique():,} | {top3:.1%} |")
    # 各来源的测试结果
    t = Encoded(test, "y_")
    maj = Encoded(pd.read_parquet(PRED / "T2_temporal_majority.parquet").set_index("cve_id").loc[test["cve_id"]].reset_index())
    lines += ["\n时间划分测试集中各来源（≥ 200 条）的结果：平均宏 F1 / 等级准确率\n", "| 来源 | 类型 | n | 多数类 | TF-IDF | DeBERTa | DeBERTa + 辅助 |", "|---|---|---|---|---|---|---|"]
    for s, n in test["source"].value_counts().items():
        if n < 200:
            continue
        idx = np.flatnonzero(test["source"].to_numpy() == s)
        cells = [fast_scores(t, maj, idx)]
        for key in ["tfidf", "none", "aux"]:
            rs = [fast_scores(t, e, idx) for e in preds[key]]
            cells.append({k: np.mean([r[k] for r in rs]) for k in ["mean_macro_f1", "band_acc"]})
        lines.append(f"| {s} | {test.loc[idx[0], 'label_type']} | {n:,} | " + " | ".join(f"{c['mean_macro_f1']:.3f} / {c['band_acc']:.3f}" for c in cells) + " |")


# ---------------- C ----------------
def vendors(ids):
    want = set(ids)
    out = {}
    with zipfile.ZipFile(ROOT / "data" / "raw" / "cves.zip") as z:
        for n in z.namelist():
            base = n.rsplit("/", 1)[-1][:-5] if n.endswith(".json") else None
            if base in want:
                cna = ((orjson.loads(z.read(n)).get("containers") or {}).get("cna") or {})
                aff = cna.get("affected") or []
                v = (aff[0].get("vendor") or "").strip().lower() if aff else ""
                out[base] = v if v and v not in ("n/a", "unknown") else None
    return out


def present_f1(t, p, idx):
    """只在真值或预测中出现的取值上求宏 F1（scikit-learn 默认），再对 11 个指标取平均。"""
    f1s = []
    for k in M40:
        n_cls = len(V40_METRICS[k])
        cm = np.bincount(t.codes[k][idx] * n_cls + p.codes[k][idx], minlength=n_cls * n_cls).reshape(n_cls, n_cls)
        tp = np.diag(cm)
        support = cm.sum(0) + cm.sum(1)
        denom = 2 * tp + (cm.sum(0) - tp) + (cm.sum(1) - tp)
        f = np.where(denom > 0, 2 * tp / np.maximum(denom, 1), 0.0)
        f1s.append(f[support > 0].mean())
    return float(np.mean(f1s))


def cluster_boot(cl, idx, stat, B=1000):
    """按簇重抽样：先抽簇，再取簇内全部 CVE。"""
    groups = defaultdict(list)
    for i in idx:
        groups[cl[i]].append(i)
    keys = list(groups)
    out = []
    for _ in range(B):
        pick = rng.integers(len(keys), size=len(keys))
        out.append(stat(np.concatenate([groups[keys[j]] for j in pick])))
    return np.percentile(out, [2.5, 97.5])


def part_c(df, test, preds, lines):
    v = vendors(test["cve_id"])
    cl = np.array([v.get(c) or c for c in test["cve_id"]])
    t = Encoded(test, "y_")
    nd = np.flatnonzero(test["label_type"].to_numpy() != "derived")
    allx = np.arange(len(test))
    lines += ["\n## C. 按厂商分簇的重抽样（时间划分测试集）\n",
              f"有厂商信息的测试 CVE {sum(1 for c in test['cve_id'] if v.get(c)):,} / {len(test):,}；簇数 {len(set(cl)):,}；最大簇 {Counter(cl).most_common(1)[0][1]:,} 条（{Counter(cl).most_common(1)[0][0]}）。\n",
              "| 比较 | 口径 | 差值 | 按 CVE 重抽样 95% 区间 | 按厂商分簇 95% 区间 |", "|---|---|---|---|---|"]

    def diff(a, b, key="mean_macro_f1"):
        def f(ix):
            return np.mean([fast_scores(t, e, ix)[key] for e in preds[a]]) - np.mean([fast_scores(t, e, ix)[key] for e in preds[b]])
        return f
    for name, idx in [("全部", allx), ("非 derived", nd)]:
        for a, b, key in [("aux", "none", "mean_macro_f1"), ("aux", "none", "band_acc"), ("aux", "tfidf", "mean_macro_f1")]:
            f = diff(a, b, key)
            pt = f(idx)
            cve = np.percentile([f(rng.choice(idx, size=len(idx), replace=True)) for _ in range(1000)], [2.5, 97.5])
            clu = cluster_boot(cl, idx, f)
            lines.append(f"| {a} − {b}（{key}） | {name} | {pt:+.3f} | [{cve[0]:+.3f}, {cve[1]:+.3f}] | [{clu[0]:+.3f}, {clu[1]:+.3f}] |")

    # 大模型样本：排名翻转（类型内分簇重抽样）+ 另一种宏 F1
    llm = pd.read_parquet(LLM / "predictions.parquet")
    ids = llm["cve_id"]
    s = df.set_index("cve_id").loc[ids].reset_index()
    ts = Encoded(s, "y_")
    e_llm = Encoded(llm.set_index("cve_id").loc[ids].reset_index())
    e_tf = Encoded(pd.read_parquet(PRED / "T2_temporal_tfidf_lr.parquet").set_index("cve_id").loc[ids].reset_index())
    aux_s = [Encoded(pd.read_parquet(d / "pred_latent.parquet").set_index("cve_id").loc[ids].reset_index())
             for d in sorted(ENC.glob("T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s[0-9]"))]
    cls = np.array([v.get(c) or c for c in s["cve_id"]])
    lt = s["label_type"].to_numpy()
    lines += ["\n大模型样本（2,000 条）：DeepSeek − TF-IDF 的平均宏 F1 差；分簇重抽样在各类型内分别按厂商进行\n",
              "| 口径 | 差值 | 按 CVE（类型内）95% 区间 | 按厂商分簇（类型内）95% 区间 |", "|---|---|---|---|"]
    for name, types in [("样本整体", ["derived", "independent", "v4_only", "other"]), ("非 derived", ["independent", "v4_only", "other"])]:
        strata = [np.flatnonzero(lt == ty) for ty in types]
        idx = np.concatenate(strata)

        def f(ix):
            return fast_scores(ts, e_llm, ix)["mean_macro_f1"] - fast_scores(ts, e_tf, ix)["mean_macro_f1"]
        cve = np.percentile([f(np.concatenate([rng.choice(x, size=len(x), replace=True) for x in strata])) for _ in range(1000)], [2.5, 97.5])
        clu_draws = []
        grp = [defaultdict(list) for _ in strata]
        for gi, x in enumerate(strata):
            for i in x:
                grp[gi][cls[i]].append(i)
        for _ in range(1000):
            parts = []
            for g in grp:
                keys = list(g)
                pick = rng.integers(len(keys), size=len(keys))
                parts.append(np.concatenate([g[keys[j]] for j in pick]))
            clu_draws.append(f(np.concatenate(parts)))
        clu = np.percentile(clu_draws, [2.5, 97.5])
        lines.append(f"| {name} | {f(idx):+.3f} | [{cve[0]:+.3f}, {cve[1]:+.3f}] | [{clu[0]:+.3f}, {clu[1]:+.3f}] |")

    lines += ["\n另一种宏 F1（只在真值或预测中出现的取值上平均）：大模型样本各方法\n",
              "| 方法 | 样本整体 | 非 derived | derived | independent | v4-only | other |", "|---|---|---|---|---|---|---|"]
    scopes = [np.arange(len(s)), np.flatnonzero(lt != "derived")] + [np.flatnonzero(lt == ty) for ty in ["derived", "independent", "v4_only", "other"]]
    for name, es in [("DeepSeek-V4-Pro", [e_llm]), ("TF-IDF + LR", [e_tf]), ("DeBERTa + 辅助（5 种子）", aux_s)]:
        lines.append(f"| {name} | " + " | ".join(f"{np.mean([present_f1(ts, e, ix) for e in es]):.3f}" for ix in scopes) + " |")
    d_pool = present_f1(ts, e_llm, scopes[0]) - present_f1(ts, e_tf, scopes[0])
    d_nd = present_f1(ts, e_llm, scopes[1]) - present_f1(ts, e_tf, scopes[1])
    boots = []
    strata = [np.flatnonzero(lt == ty) for ty in ["derived", "independent", "v4_only", "other"]]
    for _ in range(1000):
        b = [rng.choice(x, size=len(x), replace=True) for x in strata]
        pool, ndx = np.concatenate(b), np.concatenate(b[1:])
        boots.append((present_f1(ts, e_llm, pool) - present_f1(ts, e_tf, pool), present_f1(ts, e_llm, ndx) - present_f1(ts, e_tf, ndx)))
    boots = np.array(boots)
    lines.append(f"\n按这种宏 F1，DeepSeek − TF-IDF：样本整体 {d_pool:+.3f} [{np.percentile(boots[:, 0], 2.5):+.3f}, {np.percentile(boots[:, 0], 97.5):+.3f}]；"
                 f"非 derived {d_nd:+.3f} [{np.percentile(boots[:, 1], 2.5):+.3f}, {np.percentile(boots[:, 1], 97.5):+.3f}]。")
    # 主结果的另一种宏 F1
    lines += ["\n时间划分测试集，另一种宏 F1：全部 / 非 derived\n", "| 方法 | 全部 | 非 derived |", "|---|---|---|"]
    for name, key in [("TF-IDF", "tfidf"), ("DeBERTa", "none"), ("DeBERTa + 辅助", "aux")]:
        lines.append(f"| {name} | {np.mean([present_f1(t, e, allx) for e in preds[key]]):.3f} | {np.mean([present_f1(t, e, nd) for e in preds[key]]):.3f} |")


# ---------------- D ----------------
def bands_from(frame):
    vec = frame[M40].apply(to_vector, axis=1)
    return np.array([SEVERITY_ORDER.get(v4_score(x)[1], -1) for x in vec])


def decision_metrics(tb, pb):
    hc_t, hc_p = tb >= 3, pb >= 3
    return {"band": (tb == pb).mean(), "under": (pb < tb).mean(), "over": (pb > tb).mean(),
            "hc_prec": (hc_t & hc_p).sum() / max(hc_p.sum(), 1), "hc_rec": (hc_t & hc_p).sum() / max(hc_t.sum(), 1),
            "escalate": hc_p.mean(), "severe": (np.abs(pb - tb) >= 2).mean()}


def part_d(df, test, lines):
    tb = bands_from(test.rename(columns={"y_" + k: k for k in M40}))
    runs = sorted(ENC.glob("T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s[0-9]"))
    by_alpha = defaultdict(list)
    for d in runs:
        z = np.load(d / "probs.npz")
        pos = pd.Series(np.arange(len(test)), index=test["cve_id"]).loc[z["test_cve_id"]].to_numpy()
        tbx = tb[pos]
        chosen = json.loads((d / "risk_decode.json").read_text(encoding="utf-8"))["chosen_alpha"]
        for a in ALPHAS:
            pb = bands_from(decode({k: z[f"test_{k}"] for k in M40}, a))
            m = decision_metrics(tbx, pb)
            by_alpha[a].append(m)
            if abs(a - chosen) < 1e-9:
                by_alpha["chosen"].append(m)
    keys = ["band", "under", "over", "hc_prec", "hc_rec", "escalate", "severe"]
    lines += ["\n## D. 风险敏感解码的决策指标（DeBERTa + 辅助，时间划分测试集，5 种子平均）\n",
              "| 解码 | 等级准确率 | 低估率 | 高估率 | H+C 精确率 | H+C 召回 | 升级比例（预测为 H/C） | 跨两档及以上的错误 |", "|---|---|---|---|---|---|---|---|"]
    for a in [1.0, "chosen"] + [x for x in ALPHAS if x < 1.0]:
        ms = by_alpha[a]
        lines.append(f"| {'argmax' if a == 1.0 else ('验证集选定的 α' if a == 'chosen' else f'α = {a:.1f}')} | " + " | ".join(f"{np.mean([m[k] for m in ms]):.3f}" for k in keys) + " |")
    lines.append(f"\n真值中 High/Critical 的比例：{(tb >= 3).mean():.3f}")
    # 期望代价：每个 CVE 低估记 r、高估记 1
    lines += ["\n期望代价（每条低估计 r、高估计 1；各 α 下的测试集值，DeBERTa + 辅助取 5 种子平均；TF-IDF 与流水线取 risk_baselines 的扫描）\n",
              "| 方法 | r = 1 时代价最低的 α | r = 2 | r = 5 | r = 10 |", "|---|---|---|---|---|"]
    curves = {"DeBERTa + 辅助": {a: (np.mean([m["under"] for m in by_alpha[a]]), np.mean([m["over"] for m in by_alpha[a]])) for a in ALPHAS}}
    rb = json.loads((ROOT / "results" / "review_checks" / "risk_baselines_temporal.json").read_text(encoding="utf-8"))
    for name, key in [("TF-IDF", "tfidf"), ("流水线（规则 R）", "pipeline_R")]:
        curves[name] = {r["alpha"]: (r["test_under_rate"], 1 - r["test_band_acc"] - r["test_under_rate"]) for r in rb[key]["scan"]}
    for name, c in curves.items():
        cells = []
        for r in (1, 2, 5, 10):
            costs = {a: r * u + o for a, (u, o) in c.items()}
            best = min(costs, key=costs.get)
            cells.append(f"α = {best:.1f}（代价 {costs[best]:.3f}；argmax {costs[1.0]:.3f}）")
        lines.append(f"| {name} | " + " | ".join(cells) + " |")


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    ids = test["cve_id"]
    preds = {"tfidf": [Encoded(pd.read_parquet(PRED / "T2_temporal_tfidf_lr.parquet").set_index("cve_id").loc[ids].reset_index())],
             "none": [Encoded(pd.read_parquet(d / "pred_latent.parquet").set_index("cve_id").loc[ids].reset_index())
                      for d in sorted(ENC.glob("T2_temporal_deberta-v3-base_none_e5_cwinv_sqrt_s[0-9]"))],
             "aux": [Encoded(pd.read_parquet(d / "pred_latent.parquet").set_index("cve_id").loc[ids].reset_index())
                     for d in sorted(ENC.glob("T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s[0-9]"))]}
    lines = ["# 第六份审稿意见的第二类分析（自动生成）\n"]
    for step in (lambda: part_a(df, lines), lambda: part_b(df, test, preds, lines), lambda: part_c(df, test, preds, lines), lambda: part_d(df, test, lines)):
        step()
        OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print("\n".join(lines[-6:]), flush=True)
    print("\n".join(lines))


if __name__ == "__main__":
    main()
