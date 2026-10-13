"""配对来源分析：把 v3.1 换算成 v4.0 时，"用谁的 v3.1"会在多大程度上决定评测结果？

背景：Vieira et al., Internet of Things 39 (2026) 102038 在"NVD 中两版都有官方评分的 CVE"（D4，25,437 条，
快照 2026-07-12）上评测 v3.x→v4.0 转换，但没有说明用的是 NVD 自评的 v3.x 还是 CNA 的 v3.x。
本脚本用 NVD API 扫描数据（probe/nvd_v4_records.jsonl）近似重建 D4，并用同一条规则 R 比较：
  跨来源配对：NVD 的 v3.1 ↔ CNA 的 v4.0
  同来源配对：CNA 的 v3.1 ↔ 同一个 CNA 的 v4.0
  严格配对：同一批 CVE 同时有 NVD v3.1 与 CNA v3.1，只换 v3.1 的来源
输出：results/pairing_provenance/summary.md
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
    lines = [f"# 配对来源分析（近似 Vieira 2026 的 D4：{START} 至 {END} 发布、同时有 v3.1 与 v4.0，共 {len(d4):,} 条）\n"]
    src = collections.Counter(r["v40"][0][0] for r in d4)
    lines.append("v4.0 标签来源前 5：" + "；".join(f"{s} {n:,}（{n / len(d4):.1%}）" for s, n in src.most_common(5)) + "\n")

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
        ("跨来源（NVD v3.1 ↔ CNA v4.0），全部可用", d4, nvd_v31),
        ("同来源（CNA v3.1 ↔ CNA v4.0），全部可用", d4, cna_v31),
        ("同来源，去掉 VulDB", [r for r in d4 if r["v40"][0][0] != VULDB], cna_v31),
        ("严格配对 · 用 NVD 的 v3.1", paired, nvd_v31),
        ("严格配对 · 用 CNA 的 v3.1", paired, cna_v31),
        ("严格配对去掉 VulDB · 用 NVD 的 v3.1", [r for r in paired if r["v40"][0][0] != VULDB], nvd_v31),
        ("严格配对去掉 VulDB · 用 CNA 的 v3.1", [r for r in paired if r["v40"][0][0] != VULDB], cna_v31),
    ]
    lines += ["| 设定 | n | 其中 VulDB | 规则 R 等级准确率 | 低估率 | 整向量全对 |", "|---|---|---|---|---|---|"]
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
    lines.append(f"\n严格配对的 {len(paired):,} 条 CVE 上，NVD 与 CNA 的 v3.1 向量完全相同 {same / len(paired):.1%}；逐指标一致率："
                 + "，".join(f"{k} {v / len(paired):.1%}" for k, v in agree.items()))
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "summary.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
