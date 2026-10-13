"""标签来源体检：每个来源的 v4.0 向量，在多大程度上是其 v3.1 向量的确定性函数？（与具体规则无关）

对每个同来源 v3.1/v4.0 对 ≥ 100 的来源计算：
  rule_*     若干条固定换算规则的整向量命中率（规则 R 及其变体，用于敏感性分析）
  FD_in      样本内函数依赖度：按 v3.1 向量分组，组内取出现最多的 v4 向量，命中比例
             = 任何"只看 v3.1 的确定性函数"能达到的上限
  FD_oos     样本外函数依赖度：按时间取该来源前 70% 学"v3.1→最常见 v4"的映射，在后 30% 上检验；
             没见过的 v3.1 向量退回规则 R
  per-metric 各 v4 特有指标（AT/UI/SC/SI/SA）的样本内确定比例
来源分型（只用 2026-01-01 之前的数据，供实验划分使用，避免用测试期标签定义分组）：
  derived      FD_oos ≥ 阈值（默认 0.90；另报 0.80 / 0.95 下的分型作敏感性分析）
  independent  有足够的对（≥100）但 FD_oos < 阈值
  v4_only      v4 标签 ≥ 100 且同来源配对率 < 5%
另外报告：主要来源按季度的规则 R 命中率（换算习惯随时间的变化），以及"有效独立标签"数量。
输出：results/label_provenance/summary.md、source_types.json
"""

THRESHOLD = 0.90
SENSITIVITY = [0.80, 0.90, 0.95]

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import CUTOFF, M31, M40, load  # noqa: E402
from rq1_stats import rule_convert  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "results" / "label_provenance"
V4_SPECIFIC = ["AT", "UI", "SC", "SI", "SA"]


def variant(v31, ui_r="P", sub_from_scope=True):
    out = rule_convert(v31)
    if v31["UI"] == "R":
        out["UI"] = ui_r
    if not sub_from_scope:
        out.update({"SC": "N", "SI": "N", "SA": "N"})
    return out


RULES = {
    "R（UI:R→P，S:C 照抄）": dict(ui_r="P", sub_from_scope=True),
    "UI:R→A": dict(ui_r="A", sub_from_scope=True),
    "后续影响恒为 N": dict(ui_r="P", sub_from_scope=False),
    "UI:R→A 且后续恒 N": dict(ui_r="A", sub_from_scope=False),
}


def analyse(pairs):
    """pairs: 按时间排序的 [(v31_tuple, v31_dict, v4_tuple, v4_dict)]"""
    n = len(pairs)
    res = {"n_pairs": n}
    for name, kw in RULES.items():
        res[name] = sum(tuple(variant(d31, **kw)[k] for k in M40) == t4 for _, d31, t4, _ in pairs) / n
    groups = defaultdict(Counter)
    for t31, _, t4, _ in pairs:
        groups[t31][t4] += 1
    res["FD_in"] = sum(c.most_common(1)[0][1] for c in groups.values()) / n
    res["n_distinct_v31"] = len(groups)
    for k in V4_SPECIFIC:
        i = M40.index(k)
        g = defaultdict(Counter)
        for t31, _, t4, _ in pairs:
            g[t31][t4[i]] += 1
        res["det_" + k] = sum(c.most_common(1)[0][1] for c in g.values()) / n
    cut = int(0.7 * n)
    learn = defaultdict(Counter)
    for t31, _, t4, _ in pairs[:cut]:
        learn[t31][t4] += 1
    mapping = {k: c.most_common(1)[0][0] for k, c in learn.items()}
    test = pairs[cut:]
    hits = [mapping.get(t31, tuple(rule_convert(d31)[k] for k in M40)) == t4 for t31, d31, t4, _ in test]
    res["FD_oos"] = sum(hits) / len(hits) if hits else float("nan")
    res["oos_unseen_v31"] = sum(t31 not in mapping for t31, _, _, _ in test) / len(test) if test else float("nan")
    return res


def collect(df):
    by_src = defaultdict(list)
    for r in df[df["has_v31"]].sort_values("pub").itertuples():
        d31 = {k: getattr(r, "x31_" + k) for k in M31}
        d40 = {k: getattr(r, "y_" + k) for k in M40}
        by_src[r.source].append((tuple(d31[k] for k in M31), d31, tuple(d40[k] for k in M40), d40))
    return by_src


def main():
    df = load()
    n_v4 = df["source"].value_counts()
    all_pairs, pre_pairs = collect(df), collect(df[df["pub"] < CUTOFF])
    n_v4_pre = df[df["pub"] < CUTOFF]["source"].value_counts()

    rows = {s: analyse(p) | {"n_v4": int(n_v4[s])} for s, p in all_pairs.items() if len(p) >= 100}
    types, fd_pre = {}, {}
    for s, cnt in n_v4_pre.items():
        p = pre_pairs.get(s, [])
        if len(p) >= 100:
            fd_pre[s] = analyse(p)["FD_oos"]
            types[s] = {"type": "derived" if fd_pre[s] >= THRESHOLD else "independent", "FD_oos_pre2026": fd_pre[s], "n_pairs_pre2026": len(p)}
        elif cnt >= 100 and len(p) / cnt < 0.05:
            types[s] = {"type": "v4_only", "n_v4_pre2026": int(cnt)}

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "source_types.json").write_text(json.dumps(types, indent=1, ensure_ascii=False), encoding="utf-8")

    lines = ["# 标签来源体检（全时段；同来源 v3.1/v4.0 对 ≥ 100 的来源）\n",
             "| 来源 | v4 总数 | 对数 | 不同 v3.1 向量数 | " + " | ".join(RULES) + " | FD_in | **FD_oos** | " + " | ".join(f"确定-{k}" for k in V4_SPECIFIC) + " |",
             "|---" * (5 + len(RULES) + 1 + len(V4_SPECIFIC)) + "|"]
    for s, r in sorted(rows.items(), key=lambda x: -x[1]["n_pairs"]):
        lines.append(f"| {s} | {r['n_v4']:,} | {r['n_pairs']:,} | {r['n_distinct_v31']} | " + " | ".join(f"{r[k]:.1%}" for k in RULES)
                     + f" | {r['FD_in']:.1%} | **{r['FD_oos']:.1%}** | " + " | ".join(f"{r['det_' + k]:.1%}" for k in V4_SPECIFIC) + " |")
    lines.append(f"\n## 来源分型（只用 2026-01-01 之前的数据；阈值 FD_oos ≥ {THRESHOLD:.0%} 判为 derived）\n")
    for t in ["derived", "independent", "v4_only"]:
        members = [f"{s}（{v.get('FD_oos_pre2026', float('nan')):.1%}）" if t != "v4_only" else f"{s}（n={v['n_v4_pre2026']}）"
                   for s, v in types.items() if v["type"] == t]
        lines.append(f"- **{t}**：" + "，".join(members))
    share = {t: sum(n_v4.get(s, 0) for s, v in types.items() if v["type"] == t) / len(df) for t in ["derived", "independent", "v4_only"]}
    lines.append("\n全部 v4 标签中各类型占比（按上面的分型）：" + "，".join(f"{t} {x:.1%}" for t, x in share.items())
                 + f"，未分型（小来源）{1 - sum(share.values()):.1%}")
    lines.append("\n阈值敏感性（被判为 derived 的来源）：" + "；".join(
        f"≥{th:.0%}：" + ("、".join(s for s, f in fd_pre.items() if f >= th) or "无") for th in SENSITIVITY))

    # 按季度的规则 R 命中率（对数 ≥ 500 的来源；季度内对数 ≥ 30 才报告）
    lines.append("\n## 主要来源按季度的规则 R 整向量命中率\n")
    p = df[df["has_v31"]].copy()
    p["q"] = p["pub"].dt.tz_convert(None).dt.to_period("Q").astype(str)
    p["R"] = [rule_convert({k: r["x31_" + k] for k in M31}) == {k: r["y_" + k] for k in M40} for _, r in p.iterrows()]
    for s in [s for s, pp in all_pairs.items() if len(pp) >= 500]:
        g = p[p["source"] == s].groupby("q")["R"].agg(["size", "mean"])
        g = g[g["size"] >= 30]
        lines.append(f"- {s}：" + "，".join(f"{q} {m:.0%}（n={int(n)}）" for q, (n, m) in g.iterrows()))

    # 有效独立标签：只给 v4 的标签 + 与规则 R 不一致的同来源对（与 R 一致 ≠ 一定是换算，只是上界估计）
    pairs_all = df[df["has_v31"]]
    r_hit = p["R"].sum()
    lines.append(f"\n## 有效标签估计\n\n- v4 标签总数 {len(df):,}；其中只给 v4（无同来源 v3.1）{len(df) - len(pairs_all):,}；"
                 f"同来源对 {len(pairs_all):,}，其中与规则 R 完全一致 {int(r_hit):,}（{r_hit / len(pairs_all):.1%}）")
    lines.append(f"- 与 R(v3.1) 不一致或没有 v3.1 的标签（「携带 v3.1 之外信息」的上界）：{len(df) - int(r_hit):,}（占 {(len(df) - r_hit) / len(df):.1%}）")
    (OUT_DIR / "summary.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
