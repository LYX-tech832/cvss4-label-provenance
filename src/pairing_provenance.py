"""Pairing provenance: when v3.1 is converted to v4.0, how much does "whose v3.1 vector is used" determine the evaluation result?

Vieira et al., Internet of Things 39 (2026) 102038 evaluate the v3.x -> v4.0 conversion on "CVEs with official scores of both versions
in the NVD" (D4, 25,437 CVEs, snapshot of 2026-07-12), but do not state whether the v3.x vector is the NVD's own or the CNA's.
This script approximately rebuilds D4 from the NVD API scan (probe/nvd_v4_records.jsonl) and compares, with the same rule R:
  cross-source pairing: the NVD's v3.1 <-> the CNA's v4.0
  same-source pairing:  the CNA's v3.1 <-> the same CNA's v4.0
  strict pairing:       the same CVEs with both an NVD v3.1 and a CNA v3.1 vector; only the source of the v3.1 vector changes
Output: results/pairing_provenance/summary.md
"""

import collections
import io
import json
import sys
from pathlib import Path

from cvss import CVSS4

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cvss_utils import base_vector, parse_vector  # noqa: E402
from rq1_stats import rule_convert  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "pairing_provenance"
START, END = "2023-11-01", "2026-07-12"   # 与 Vieira 2026 的 D4 口径一致
NVD, VULDB = "nvd@nist.gov", "cna@vuldb.com"
ORDER = {"None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
_band = {}


def band(vec):
    if vec not in _band:
        _band[vec] = CVSS4(vec).severity
    return _band[vec]


def convert(v31):
    p = parse_vector(v31, "3.1")
    return base_vector(rule_convert(p), "4.0") if p else None


def main():
    recs = [json.loads(line) for line in io.open(ROOT / "probe" / "nvd_v4_records.jsonl", encoding="utf-8")]
    d4 = [r for r in recs if START <= r["published"][:10] <= END and r["v31"] and r["v40"]]
    lines = [f"# Pairing provenance (approximation of D4 of Vieira et al. 2026: published from {START} to {END}, with both v3.1 and v4.0, {len(d4):,} CVEs)\n"]
    src = collections.Counter(r["v40"][0][0] for r in d4)
    lines.append("Top 5 sources of the v4.0 labels: " + "; ".join(f"{s} {n:,} ({n / len(d4):.1%})" for s, n in src.most_common(5)) + "\n")

    def evaluate(rows, pick_v31):
        c = collections.Counter()
        for r in rows:
            s40, v40 = r["v40"][0][0], r["v40"][0][2]
            p40 = parse_vector(v40, "4.0")
            v31 = pick_v31(r)
            cv = convert(v31) if v31 else None
            if not p40 or not cv:
                continue
            tb, pb = band(base_vector(p40, "4.0")), band(cv)
            c["n"] += 1
            c["band"] += pb == tb
            c["under"] += ORDER[pb] < ORDER[tb]
            c["exact"] += cv == base_vector(p40, "4.0")
            c["vuldb"] += s40 == VULDB
        return c

    by_src = lambda r: {s: v for s, _, v in r["v31"]}  # noqa: E731
    nvd_v31 = lambda r: by_src(r).get(NVD) if r["v40"][0][0] != NVD else None  # noqa: E731
    cna_v31 = lambda r: by_src(r).get(r["v40"][0][0])  # noqa: E731
    paired = [r for r in d4 if nvd_v31(r) and cna_v31(r)]
    rows = [
        ("cross-source (NVD v3.1 ↔ CNA v4.0), all available", d4, nvd_v31),
        ("same-source (CNA v3.1 ↔ CNA v4.0), all available", d4, cna_v31),
        ("same-source, without VulDB", [r for r in d4 if r["v40"][0][0] != VULDB], cna_v31),
        ("strict pairing · NVD's v3.1", paired, nvd_v31),
        ("strict pairing · CNA's v3.1", paired, cna_v31),
        ("strict pairing without VulDB · NVD's v3.1", [r for r in paired if r["v40"][0][0] != VULDB], nvd_v31),
        ("strict pairing without VulDB · CNA's v3.1", [r for r in paired if r["v40"][0][0] != VULDB], cna_v31),
    ]
    lines += ["| Setting | n | Of which VulDB | Rule-R band accuracy | Underestimation | Exact vector |", "|---|---|---|---|---|---|"]
    for name, subset, pick in rows:
        c = evaluate(subset, pick)
        n = c["n"]
        lines.append(f"| {name} | {n:,} | {c['vuldb'] / n:.1%} | {c['band'] / n:.1%} | {c['under'] / n:.1%} | {c['exact'] / n:.1%} |")

    agree, same = collections.Counter(), 0
    for r in paired:
        a, b = parse_vector(nvd_v31(r), "3.1"), parse_vector(cna_v31(r), "3.1")
        if a and b:
            same += a == b
            for k in a:
                agree[k] += a[k] == b[k]
    lines.append(f"\nOn the {len(paired):,} strictly paired CVEs, the NVD's and the CNA's v3.1 vectors are identical for {same / len(paired):.1%}; per-metric agreement: "
                 + ", ".join(f"{k} {v / len(paired):.1%}" for k, v in agree.items()))
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "summary.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
