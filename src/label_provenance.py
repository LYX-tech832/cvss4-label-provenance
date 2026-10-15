"""Label provenance audit: to what extent is each source's v4.0 vector a deterministic function of its own v3.1 vector? (Independent of any particular rule.)

For each source with at least 100 same-source v3.1/v4.0 pairs:
  rule_*     exact-vector hit rate of several fixed conversion rules (rule R and its variants, for the sensitivity analysis)
  FD_in      in-sample functional dependence: group the pairs by v3.1 vector, take the most frequent v4 vector of each group, share of hits
             = the upper bound for any deterministic function of the v3.1 vector alone
  FD_oos     out-of-sample functional dependence: learn the mapping "v3.1 -> most frequent v4" on the source's earliest 70% (by time),
             test it on the remaining 30%; v3.1 vectors not seen in training fall back to rule R
  per-metric in-sample deterministic share of each v4-specific metric (AT/UI/SC/SI/SA)
Source typing (uses only data before 2026-01-01, so that the groups used by the splits are not defined with labels of the test period):
  derived      FD_oos >= threshold (default 0.90; the typing at 0.80 and 0.95 is reported as a sensitivity analysis)
  independent  enough pairs (>= 100) but FD_oos < threshold
  v4_only      at least 100 v4 labels and a same-source pairing rate below 5%
Also reported: the quarterly rule-R hit rate of the main sources (changes of conversion practice over time) and an estimate of the labels
that carry information beyond the v3.1 vector.
Output: results/label_provenance/summary.md, source_types.json
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
    "R (UI:R→P, S:C copied)": dict(ui_r="P", sub_from_scope=True),
    "UI:R→A": dict(ui_r="A", sub_from_scope=True),
    "subsequent impacts always N": dict(ui_r="P", sub_from_scope=False),
    "UI:R→A and subsequent always N": dict(ui_r="A", sub_from_scope=False),
}


def analyse(pairs):
    """pairs: [(v31_tuple, v31_dict, v4_tuple, v4_dict)] sorted by time"""
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

    lines = ["# Label provenance audit (all periods; sources with at least 100 same-source v3.1/v4.0 pairs)\n",
             "| Source | v4 labels | Pairs | Distinct v3.1 vectors | " + " | ".join(RULES) + " | FD_in | **FD_oos** | " + " | ".join(f"det-{k}" for k in V4_SPECIFIC) + " |",
             "|---" * (5 + len(RULES) + 1 + len(V4_SPECIFIC)) + "|"]
    for s, r in sorted(rows.items(), key=lambda x: -x[1]["n_pairs"]):
        lines.append(f"| {s} | {r['n_v4']:,} | {r['n_pairs']:,} | {r['n_distinct_v31']} | " + " | ".join(f"{r[k]:.1%}" for k in RULES)
                     + f" | {r['FD_in']:.1%} | **{r['FD_oos']:.1%}** | " + " | ".join(f"{r['det_' + k]:.1%}" for k in V4_SPECIFIC) + " |")
    lines.append(f"\n## Source typing (data before 2026-01-01 only; FD_oos ≥ {THRESHOLD:.0%} means derived)\n")
    for t in ["derived", "independent", "v4_only"]:
        members = [f"{s} ({v.get('FD_oos_pre2026', float('nan')):.1%})" if t != "v4_only" else f"{s} (n={v['n_v4_pre2026']})"
                   for s, v in types.items() if v["type"] == t]
        lines.append(f"- **{t}**: " + ", ".join(members))
    share = {t: sum(n_v4.get(s, 0) for s, v in types.items() if v["type"] == t) / len(df) for t in ["derived", "independent", "v4_only"]}
    lines.append("\nShare of each type among all v4 labels (typing above): " + ", ".join(f"{t} {x:.1%}" for t, x in share.items())
                 + f", untyped (small sources) {1 - sum(share.values()):.1%}")
    lines.append("\nThreshold sensitivity (sources typed as derived): " + "; ".join(
        f"≥{th:.0%}: " + (", ".join(s for s, f in fd_pre.items() if f >= th) or "none") for th in SENSITIVITY))

    # 按季度的规则 R 命中率（对数 ≥ 500 的来源；季度内对数 ≥ 30 才报告）
    lines.append("\n## Quarterly exact-vector hit rate of rule R for the main sources\n")
    p = df[df["has_v31"]].copy()
    p["q"] = p["pub"].dt.tz_convert(None).dt.to_period("Q").astype(str)
    p["R"] = [rule_convert({k: r["x31_" + k] for k in M31}) == {k: r["y_" + k] for k in M40} for _, r in p.iterrows()]
    for s in [s for s, pp in all_pairs.items() if len(pp) >= 500]:
        g = p[p["source"] == s].groupby("q")["R"].agg(["size", "mean"])
        g = g[g["size"] >= 30]
        lines.append(f"- {s}: " + ", ".join(f"{q} {m:.0%} (n={int(n)})" for q, (n, m) in g.iterrows()))

    # 有效独立标签：只给 v4 的标签 + 与规则 R 不一致的同来源对（与 R 一致 ≠ 一定是换算，只是上界估计）
    pairs_all = df[df["has_v31"]]
    r_hit = p["R"].sum()
    lines.append(f"\n## Labels that carry information beyond the v3.1 vector\n\n- v4 labels in total {len(df):,}; of these, v4 only (no same-source v3.1) {len(df) - len(pairs_all):,}; "
                 f"same-source pairs {len(pairs_all):,}, of which identical to rule R {int(r_hit):,} ({r_hit / len(pairs_all):.1%})")
    lines.append(f"- Labels that differ from R(v3.1) or have no v3.1 vector (upper bound of the labels that carry information beyond the v3.1 vector): {len(df) - int(r_hit):,} ({(len(df) - r_hit) / len(df):.1%})")
    (OUT_DIR / "summary.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
