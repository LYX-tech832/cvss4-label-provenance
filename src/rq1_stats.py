"""RQ1：v4.0 标签的数量、来源构成、v3.1→v4.0 换算规律（基于 CVE List V5 快照）。

输入：data/processed/cve_records.parquet（由 build_cvelist_dataset.py 生成）
输出：results/rq1/rq1_summary.md 和 rq1_summary.json

口径说明：
- "来源"= CVE 记录里 CNA 容器的 providerMetadata.shortName；ADP（如 CISA-ADP）单独统计。
- "同来源双版本对"= 同一个 CNA 容器里同时有有效的 v3.1 和 v4.0 基础向量（各取第一个）。
- 规则换算 R（用于检验"是否按固定规则从 v3.1 换算"）：
    AV/AC/PR 照抄；AT=N；UI: N→N, R→P；VC/VI/VA = C/I/A；
    SC/SI/SA = 若 S:C 则照抄 C/I/A，否则全为 N。
"""

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cvss_utils import V40_METRICS, parse_vector  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "results" / "rq1"
TOP_SOURCES = 12


def rule_convert(v31):
    sub = {"SC": v31["C"], "SI": v31["I"], "SA": v31["A"]} if v31["S"] == "C" else {"SC": "N", "SI": "N", "SA": "N"}
    return {
        "AV": v31["AV"], "AC": v31["AC"], "AT": "N", "PR": v31["PR"],
        "UI": "N" if v31["UI"] == "N" else "P",
        "VC": v31["C"], "VI": v31["I"], "VA": v31["A"], **sub,
    }


def pct(a, b):
    return f"{a / b:.1%}" if b else "-"


def main():
    df = pd.read_parquet(ROOT / "data" / "processed" / "cve_records.parquet")
    df["pub"] = pd.to_datetime(df["date_published"], utc=True, errors="coerce")
    df["year"] = df["pub"].dt.year
    has40 = df["cna_v40"].str.len() > 0
    has31 = df["cna_v31"].str.len() > 0
    adp31 = df["adp_v31"].str.len() > 0
    adp40 = df["adp_v40"].str.len() > 0
    no_score = ~(has40 | has31 | adp31 | adp40)
    lines, js = [], {}

    # 1) 按发布年份的数量
    lines.append("## 1. 按发布年份（CVE List V5 快照，PUBLISHED 记录）\n")
    lines.append("| 年份 | CVE 数 | CNA 给 v4.0 | CNA 给 v3.1 | CNA 同时给两版 | ADP 给 v3.1 | ADP 给 v4.0 | 完全无 v3.1/v4.0 |")
    lines.append("|---|---|---|---|---|---|---|---|")
    js["by_year"] = {}
    for y in range(2016, int(df["year"].max()) + 1):
        m = df["year"] == y
        n = int(m.sum())
        row = [int((m & has40).sum()), int((m & has31).sum()), int((m & has40 & has31).sum()),
               int((m & adp31).sum()), int((m & adp40).sum()), int((m & no_score).sum())]
        js["by_year"][y] = [n] + row
        lines.append(f"| {y} | {n:,} | {row[0]:,} ({pct(row[0], n)}) | {row[1]:,} ({pct(row[1], n)}) | {row[2]:,} | {row[3]:,} | {row[4]:,} | {row[5]:,} ({pct(row[5], n)}) |")
    tot40 = int(has40.sum())
    lines.append(f"\n全部年份合计：CNA 给 v4.0 的 CVE **{tot40:,}** 条；CNA 同时给 v3.1 和 v4.0 的 **{int((has40 & has31).sum()):,}** 条；ADP 给 v4.0 的 {int(adp40.sum()):,} 条。\n")

    # 2) v4.0 标签来源
    v4 = df[has40].copy()
    src = v4["cna_short_name"].fillna("UNKNOWN").value_counts()
    js["n_v40_sources"] = int(src.size)
    lines.append(f"## 2. v4.0 标签来源（CNA shortName，共 {src.size} 个）\n")
    lines.append("| 来源 | 条数 | 占比 |\n|---|---|---|")
    for s, c in src.head(TOP_SOURCES).items():
        lines.append(f"| {s} | {c:,} | {pct(c, len(v4))} |")
    lines.append("\n各年份前三来源：")
    for y, g in v4.groupby("year"):
        vc = g["cna_short_name"].fillna("UNKNOWN").value_counts()
        lines.append(f"- {int(y)}（{len(g):,} 条）：" + "；".join(f"{s} {pct(c, len(g))}" for s, c in vc.head(3).items()))
    lines.append("")

    # 3) 同一 CVE 的多来源 v4.0
    multi_cna = int((v4["cna_v40"].str.len() > 1).sum())
    both_cna_adp = int((has40 & adp40).sum())
    lines.append("## 3. 同一 CVE 的多个 v4.0 标签\n")
    lines.append(f"- CNA 容器内有 ≥2 个不同 v4.0 基础向量：{multi_cna} 条")
    lines.append(f"- CNA 与 ADP 都给了 v4.0：{both_cna_adp} 条\n")

    # 4) 同来源双版本对：一致率、条件分布、规则换算命中率
    pairs = []
    for r in df[has40 & has31].itertuples():
        a, b = parse_vector(r.cna_v31[0], "3.1"), parse_vector(r.cna_v40[0], "4.0")
        if a and b:
            pairs.append((r.cna_short_name or "UNKNOWN", a, b, r.year))
    js["n_pairs"] = len(pairs)
    lines.append(f"## 4. 同一 CNA 同时给出的 v3.1–v4.0 对（{len(pairs):,} 对）\n")
    lines.append("| 对应指标 | 一致率 |\n|---|---|")
    js["agreement"] = {}
    for k31, k40 in [("AV", "AV"), ("AC", "AC"), ("PR", "PR"), ("C", "VC"), ("I", "VI"), ("A", "VA")]:
        agree = sum(a[k31] == b[k40] for _, a, b, _ in pairs)
        js["agreement"][f"{k31}->{k40}"] = agree / len(pairs)
        lines.append(f"| v3.1 {k31} → v4.0 {k40} | {pct(agree, len(pairs))} |")

    def cond(fn_a, fn_b, label):
        c = defaultdict(Counter)
        for _, a, b, _ in pairs:
            c[fn_a(a)][fn_b(b)] += 1
        out = []
        for x in sorted(c):
            n = sum(c[x].values())
            out.append(f"{label}={x}（n={n:,}）→ " + "，".join(f"{y}:{pct(v, n)}" for y, v in c[x].most_common()))
        return out

    lines.append("\n条件分布：")
    lines += ["- " + s for s in cond(lambda a: a["UI"], lambda b: "UI:" + b["UI"], "v3.1 UI")]
    lines += ["- " + s for s in cond(lambda a: a["AC"], lambda b: "AT:" + b["AT"], "v3.1 AC")]
    lines += ["- " + s for s in cond(lambda a: a["S"], lambda b: "后续系统影响" + ("≠N" if any(b[k] != "N" for k in ("SC", "SI", "SA")) else "=N"), "v3.1 S")]

    # 规则 R 的整向量命中率（按来源）
    hit = Counter(); tot = Counter()
    for s, a, b, _ in pairs:
        tot[s] += 1
        hit[s] += rule_convert(a) == b
    all_hit = sum(hit.values())
    js["rule_exact_match_all"] = all_hit / len(pairs)
    lines.append(f"\n规则换算 R 的整向量完全命中率：全部 {pct(all_hit, len(pairs))}；按来源（对数 ≥ 100）：\n")
    lines.append("| 来源 | 对数 | R 完全命中 |\n|---|---|---|")
    js["rule_exact_match_by_source"] = {}
    for s, n in tot.most_common():
        if n < 100:
            continue
        js["rule_exact_match_by_source"][s] = [n, hit[s] / n]
        lines.append(f"| {s} | {n:,} | {pct(hit[s], n)} |")

    # 5) v4.0 各指标类别分布
    lines.append("\n## 5. v4.0 各指标类别分布（CNA 的第一个 v4.0 向量）\n")
    parsed = [p for p in (parse_vector(v[0], "4.0") for v in v4["cna_v40"]) if p]
    js["class_dist"] = {}
    for k in V40_METRICS:
        c = Counter(p[k] for p in parsed)
        js["class_dist"][k] = {x: v / len(parsed) for x, v in c.items()}
        lines.append(f"- {k}：" + "，".join(f"{x}={pct(v, len(parsed))}" for x, v in c.most_common()))

    # 6) 描述与 CWE 覆盖
    lines.append("\n## 6. 文本与 CWE（v4.0 子集）\n")
    dl = v4["description"].fillna("").str.len()
    lines.append(f"- 描述长度（字符）：中位数 {int(dl.median())}，P10 {int(dl.quantile(0.1))}，P90 {int(dl.quantile(0.9))}；缺描述 {int((dl == 0).sum())} 条")
    has_cwe = (v4["cwe_cna"].str.len() > 0) | (v4["cwe_adp"].str.len() > 0)
    lines.append(f"- 带 CWE（CNA 或 ADP）：{pct(int(has_cwe.sum()), len(v4))}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "rq1_summary.md").write_text("\n".join(lines), encoding="utf-8")
    (OUT_DIR / "rq1_summary.json").write_text(json.dumps(js, indent=1, ensure_ascii=False, default=str), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
