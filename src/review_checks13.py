"""补充的一项核对（10-11；CPU，几秒；只读处理好的 CVE 记录）。

论文 5.1 节原来写"大多数新 CVE 没有来自同一来源的 v3.1 向量"，与数据不符。这里按发布年份统计：
有 CNA 提供的 v3.1 向量、有 CNA 或 ADP 的 v3.1 向量、有 CNA 提供的 v4.0 向量、CNA 两个版本都没给的 CVE 各占多少。
用来核对的已知数字：2026 年发布的 CVE 中有 CNA v4.0 向量的占 31.2%（引言）。
输出：results/review_checks/summary19.md
"""

from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "review_checks" / "summary19.md"


def main():
    df = pd.read_parquet(ROOT / "data" / "processed" / "cve_records.parquet",
                         columns=["cve_id", "date_published", "cna_v40", "cna_v31", "adp_v31"])
    has = lambda c: df[c].map(lambda v: v is not None and not isinstance(v, float) and len(v) > 0)  # noqa: E731
    v31, v40, adp = has("cna_v31"), has("cna_v40"), has("adp_v31")
    year = pd.to_datetime(df["date_published"], errors="coerce", utc=True).dt.year
    lines = ["# 按发布年份统计 CNA 提供的 CVSS 向量（自动生成）\n",
             "| 发布年份 | CVE 数 | 有 CNA v3.1 | 没有 CNA v3.1 | 有 CNA 或 ADP 的 v3.1 | 有 CNA v4.0 | CNA 两个版本都没有 |",
             "|---|---|---|---|---|---|---|"]
    for y in (2024, 2025, 2026):
        m = year == y
        n = int(m.sum())
        f = lambda x: f"{int((m & x).sum()):,} ({(m & x).sum() / n:.1%})"  # noqa: E731
        lines.append(f"| {y} | {n:,} | {f(v31)} | {f(~v31)} | {f(v31 | adp)} | {f(v40)} | {f(~v31 & ~v40)} |")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
