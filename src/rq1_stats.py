"""RQ1: number of v4.0 labels, composition of their sources, regularities of the v3.1 -> v4.0 conversion (from the CVE List V5 snapshot).

Input: data/processed/cve_records.parquet (written by build_cvelist_dataset.py)
Output: results/rq1/rq1_summary.md and rq1_summary.json

Definitions:
- "Source" = providerMetadata.shortName of the CNA container of the CVE record; ADPs (e.g. CISA-ADP) are counted separately.
- "Same-source pair" = a CNA container with valid v3.1 and v4.0 base vectors (the first of each).
- Conversion rule R (to test whether v4.0 vectors are converted from v3.1 by a fixed rule):
    AV/AC/PR copied; AT=N; UI: N->N, R->P; VC/VI/VA = C/I/A;
    SC/SI/SA = C/I/A copied if S:C, otherwise all N.
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
    lines.append("## 1. By publication year (CVE List V5 snapshot, PUBLISHED records)\n")
    lines.append("| Year | CVEs | CNA gives v4.0 | CNA gives v3.1 | CNA gives both | ADP gives v3.1 | ADP gives v4.0 | No v3.1/v4.0 at all |")
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
    lines.append(f"\nAll years: CVEs with a CNA-provided v4.0 vector **{tot40:,}**; with CNA-provided v3.1 and v4.0 vectors **{int((has40 & has31).sum()):,}**; with an ADP-provided v4.0 vector {int(adp40.sum()):,}.\n")

    # 2) v4.0 标签来源
    v4 = df[has40].copy()
    src = v4["cna_short_name"].fillna("UNKNOWN").value_counts()
    js["n_v40_sources"] = int(src.size)
    lines.append(f"## 2. Sources of the v4.0 labels (CNA shortName, {src.size} in total)\n")
    lines.append("| Source | CVEs | Share |\n|---|---|---|")
    for s, c in src.head(TOP_SOURCES).items():
        lines.append(f"| {s} | {c:,} | {pct(c, len(v4))} |")
    lines.append("\nTop three sources per year:")
    for y, g in v4.groupby("year"):
        vc = g["cna_short_name"].fillna("UNKNOWN").value_counts()
        lines.append(f"- {int(y)} ({len(g):,} CVEs): " + "; ".join(f"{s} {pct(c, len(g))}" for s, c in vc.head(3).items()))
    lines.append("")

    # 3) 同一 CVE 的多来源 v4.0
    multi_cna = int((v4["cna_v40"].str.len() > 1).sum())
    both_cna_adp = int((has40 & adp40).sum())
    lines.append("## 3. Several v4.0 labels for the same CVE\n")
    lines.append(f"- CNA container with ≥2 different v4.0 base vectors: {multi_cna} CVEs")
    lines.append(f"- Both the CNA and an ADP give a v4.0 vector: {both_cna_adp} CVEs\n")

    # 4) 同来源双版本对：一致率、条件分布、规则换算命中率
    pairs = []
    for r in df[has40 & has31].itertuples():
        a, b = parse_vector(r.cna_v31[0], "3.1"), parse_vector(r.cna_v40[0], "4.0")
        if a and b:
            pairs.append((r.cna_short_name or "UNKNOWN", a, b, r.year))
    js["n_pairs"] = len(pairs)
    lines.append(f"## 4. v3.1–v4.0 pairs given by the same CNA ({len(pairs):,} pairs)\n")
    lines.append("| Corresponding metrics | Agreement |\n|---|---|")
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
            out.append(f"{label}={x} (n={n:,}) → " + ", ".join(f"{y}:{pct(v, n)}" for y, v in c[x].most_common()))
        return out

    lines.append("\nConditional distributions:")
    lines += ["- " + s for s in cond(lambda a: a["UI"], lambda b: "UI:" + b["UI"], "v3.1 UI")]
    lines += ["- " + s for s in cond(lambda a: a["AC"], lambda b: "AT:" + b["AT"], "v3.1 AC")]
    lines += ["- " + s for s in cond(lambda a: a["S"], lambda b: "subsequent impacts" + ("≠N" if any(b[k] != "N" for k in ("SC", "SI", "SA")) else "=N"), "v3.1 S")]

    # 规则 R 的整向量命中率（按来源）
    hit = Counter(); tot = Counter()
    for s, a, b, _ in pairs:
        tot[s] += 1
        hit[s] += rule_convert(a) == b
    all_hit = sum(hit.values())
    js["rule_exact_match_all"] = all_hit / len(pairs)
    lines.append(f"\nExact-vector hit rate of conversion rule R: all {pct(all_hit, len(pairs))}; by source (at least 100 pairs):\n")
    lines.append("| Source | Pairs | Exact hit of R |\n|---|---|---|")
    js["rule_exact_match_by_source"] = {}
    for s, n in tot.most_common():
        if n < 100:
            continue
        js["rule_exact_match_by_source"][s] = [n, hit[s] / n]
        lines.append(f"| {s} | {n:,} | {pct(hit[s], n)} |")

    # 5) v4.0 各指标类别分布
    lines.append("\n## 5. Value distribution of each v4.0 metric (the CNA's first v4.0 vector)\n")
    parsed = [p for p in (parse_vector(v[0], "4.0") for v in v4["cna_v40"]) if p]
    js["class_dist"] = {}
    for k in V40_METRICS:
        c = Counter(p[k] for p in parsed)
        js["class_dist"][k] = {x: v / len(parsed) for x, v in c.items()}
        lines.append(f"- {k}: " + ", ".join(f"{x}={pct(v, len(parsed))}" for x, v in c.most_common()))

    # 6) 描述与 CWE 覆盖
    lines.append("\n## 6. Text and CWE (v4.0 subset)\n")
    dl = v4["description"].fillna("").str.len()
    lines.append(f"- Description length (characters): median {int(dl.median())}, P10 {int(dl.quantile(0.1))}, P90 {int(dl.quantile(0.9))}; missing descriptions {int((dl == 0).sum())}")
    has_cwe = (v4["cwe_cna"].str.len() > 0) | (v4["cwe_adp"].str.len() > 0)
    lines.append(f"- With a CWE (CNA or ADP): {pct(int(has_cwe.sum()), len(v4))}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "rq1_summary.md").write_text("\n".join(lines), encoding="utf-8")
    (OUT_DIR / "rq1_summary.json").write_text(json.dumps(js, indent=1, ensure_ascii=False, default=str), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
