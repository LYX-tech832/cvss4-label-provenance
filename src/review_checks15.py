"""CVEs with a v4.0 vector assigned by the NVD itself (CPU, seconds; reads only probe/nvd_v4_records.jsonl and the processed CVE records).

A few NVD records carry a v4.0 vector assigned by the NVD itself (source = nvd@nist.gov). This script lists these CVEs and marks
whether each one is in our v4.0 dataset and whether it belongs to the 16,250 v4.0-labelled CVEs with an NVD-assigned v3.1 vector.
Output: results/review_checks/summary21.md
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import load  # noqa: E402
from nvd_reference import nvd_vectors  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "review_checks" / "summary21.md"
NVD = "nvd@nist.gov"


def main():
    df = load()
    ours = dict(zip(df["cve_id"], df["source"]))
    nvd31 = set(nvd_vectors())  # 有 NVD 自评 v3.1 向量的 CVE
    both = sum(c in nvd31 for c in ours)
    rows, n = [], 0
    with (ROOT / "probe" / "nvd_v4_records.jsonl").open(encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            n += 1
            if any(e[0] == NVD for e in (r.get("v40") or [])):
                rows.append((r["id"], r["published"][:10], ours.get(r["id"], "—"), r["id"] in ours and r["id"] in nvd31))
    lines = ["# CVEs with a v4.0 vector assigned by the NVD itself (generated automatically)\n",
             f"NVD records: {n:,}; CVEs of the v4.0 dataset with an NVD-assigned v3.1 vector: {both:,}.\n",
             "| CVE | Published | CNA in the v4.0 dataset | In that set |", "|---|---|---|---|"]
    lines += [f"| {c} | {d} | {s} | {'yes' if b else 'no'} |" for c, d, s, b in rows]
    lines.append(f"\n{len(rows)} CVEs in total, {sum(b for *_, b in rows)} of them in that set.")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
