"""补充的一项核对（10-12；CPU，几秒；只读 probe/nvd_v4_records.jsonl 和处理好的 CVE 记录）。

论文 8.2 节原来写"no independent v4.0 assessment of these CVEs exists"（这些 CVE 指有 NVD 自评 v3.1 向量的
v4.0 标注 CVE，共 16,250 个）。NVD 记录里其实有极少数 CVE 带 NVD 自己给的 v4.0 向量（source = nvd@nist.gov）。
这里把它们列出来，并标明是否在我们的 v4.0 数据集里、是否属于那 16,250 个。
输出：results/review_checks/summary21.md
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
    lines = ["# NVD 自己给出 v4.0 向量的 CVE（自动生成）\n",
             f"NVD 记录 {n:,} 条；v4.0 数据集中有 NVD 自评 v3.1 向量的 CVE {both:,} 个。\n",
             "| CVE | 发布日期 | 在 v4.0 数据集中的 CNA | 属于有 NVD v3.1 的那批 |", "|---|---|---|---|"]
    lines += [f"| {c} | {d} | {s} | {'是' if b else '否'} |" for c, d, s, b in rows]
    lines.append(f"\n共 {len(rows)} 个，其中属于有 NVD v3.1 的那批的 {sum(b for *_, b in rows)} 个。")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
