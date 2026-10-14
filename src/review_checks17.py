"""NVD 参照子集的构成（CPU，约 1 分钟；只读 probe/nvd_v4_records.jsonl 和处理好的 CVE 记录）。

有 NVD 自评 v3.1 向量的测试 CVE 不是随机样本：NVD 自 2026 年 4 月 15 日起优先处理部分 CVE，各来源的覆盖率也不同。
这里给出：A. 测试集里有 NVD 向量的比例，按来源、按 4 月 15 日前后；B. 有 / 无 NVD 向量的测试 CVE 中，
CNA 标签为 High 或 Critical 的比例；C. CNA 的 v4.0 标签与 NVD 在七项上完全相同的比例，按发布时期和来源。
输出：results/review_checks/summary23.md
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import nvd_reference as nr  # noqa: E402
from baselines_v0 import CUTOFF, load, source_type_map  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "review_checks" / "summary23.md"
GROUPS = [("VulDB", "VulDB"), ("VulnCheck", "VulnCheck"), ("GitHub", "GitHub_M")]


def group(df):
    g = np.full(len(df), "其他来源", dtype=object)
    for name, src in GROUPS:
        g[(df["source"] == src).to_numpy()] = name
    return g


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    nvd = nr.nvd_vectors()
    df["has_nvd"] = df["cve_id"].isin(nvd)
    df["grp"] = group(df)
    apr = pd.Timestamp("2026-04-15", tz=df["pub"].dt.tz)
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    names = [n for n, _ in GROUPS] + ["其他来源"]
    lines = ["# NVD 参照子集的构成（自动生成）\n",
             f"时间划分测试集 {len(test):,} 条，其中有 NVD 自评 v3.1 向量的 {int(test['has_nvd'].sum()):,} 条（{test['has_nvd'].mean():.1%}）。\n",
             "## A. 有 NVD 向量的比例\n", "| 来源 | 测试 CVE | 有 NVD 向量 | 4 月 15 日前 | 4 月 15 日起 |", "|---|---|---|---|---|"]
    early, late = test["pub"] < apr, test["pub"] >= apr
    for n in names + ["合计"]:
        m = np.ones(len(test), bool) if n == "合计" else (test["grp"] == n).to_numpy()
        lines.append(f"| {n} | {int(m.sum()):,} | {test['has_nvd'][m].mean():.1%} | {test['has_nvd'][m & early].mean():.1%}（n = {int((m & early).sum()):,}） "
                     f"| {test['has_nvd'][m & late].mean():.1%}（n = {int((m & late).sum()):,}） |")
    lines.append(f"\n有 NVD 向量的测试 CVE 中发布于 4 月 15 日起的占 {(test.loc[test['has_nvd'], 'pub'] >= apr).mean():.1%}；全测试集中占 {late.mean():.1%}。\n")

    band = np.asarray(nr.Encoded(test, "y_").band)
    lines += ["## B. CNA 标签为 High 或 Critical 的比例\n", "| 来源 | 有 NVD 向量 | 无 NVD 向量 |", "|---|---|---|"]
    for n in names + ["非 derived 合计"]:
        m = (test["label_type"] != "derived").to_numpy() if n == "非 derived 合计" else (test["grp"] == n).to_numpy()
        a, b = m & test["has_nvd"].to_numpy(), m & ~test["has_nvd"].to_numpy()
        lines.append(f"| {n} | {np.mean(band[a] >= 3):.1%}（n = {int(a.sum()):,}） | {np.mean(band[b] >= 3):.1%}（n = {int(b.sum()):,}） |")

    d = df[df["has_nvd"]].reset_index(drop=True)
    ref = {k: np.array([nvd[c][0][k] for c in d["cve_id"]]) for k in ["AV", "AC", "PR", "UI", "C", "I", "A", "S"]}
    same = nr.match(nr.shared_from_v4(d, "y_"), ref).all(1)
    periods = [("2026 年以前", d["pub"] < CUTOFF), ("2026-01-01 至 04-14", (d["pub"] >= CUTOFF) & (d["pub"] < apr)), ("2026-04-15 起", d["pub"] >= apr)]
    lines += ["\n## C. CNA 的 v4.0 标签与 NVD 七项全同的比例（全部有 NVD v3.1 向量的 CVE）\n", "| 时期 | " + " | ".join(names) + " |", "|---|" + "---|" * len(names)]
    for pn, pm in periods:
        cells = []
        for n in names:
            m = (pm & (d["grp"] == n)).to_numpy()
            cells.append(f"{same[m].mean():.1%}（n = {int(m.sum()):,}）")
        lines.append(f"| {pn} | " + " | ".join(cells) + " |")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
