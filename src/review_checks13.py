"""CVSS vectors provided by CNAs, by publication year (CPU, seconds; reads only the processed CVE records).

For each publication year: the share of CVEs with a CNA-provided v3.1 vector, with a v3.1 vector from the CNA or an ADP,
with a CNA-provided v4.0 vector, and with neither version from the CNA.
Known figure for checking: 31.2% of the CVEs published in 2026 have a CNA-provided v4.0 vector (Introduction).
Output: results/review_checks/summary19.md
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
    lines = ["# CVSS vectors provided by CNAs, by publication year (generated automatically)\n",
             "| Publication year | CVEs | CNA v3.1 | No CNA v3.1 | v3.1 from the CNA or an ADP | CNA v4.0 | Neither version from the CNA |",
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
