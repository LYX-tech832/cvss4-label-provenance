"""Composition of the NVD reference subset (CPU, about 1 minute; reads only probe/nvd_v4_records.jsonl and the processed CVE records).

The test CVEs with an NVD-assigned v3.1 vector are not a random sample: since 15 April 2026 the NVD has prioritised a subset of CVEs,
and coverage differs by source. This script reports: A. the share of test CVEs with an NVD vector, by source and before and after
15 April 2026; B. the share of CNA labels rated High or Critical among the test CVEs with and without an NVD vector; C. the share of
CNA v4.0 labels that agree with the NVD on all seven shared items, by publication period and source.
Output: results/review_checks/summary23.md
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
    g = np.full(len(df), "other sources", dtype=object)
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
    names = [n for n, _ in GROUPS] + ["other sources"]
    lines = ["# Composition of the NVD reference subset (generated automatically)\n",
             f"Temporal split test set: {len(test):,} CVEs, of which {int(test['has_nvd'].sum()):,} have an NVD-assigned v3.1 vector ({test['has_nvd'].mean():.1%}).\n",
             "## A. Share with an NVD vector\n", "| Source | Test CVEs | With an NVD vector | Before 15 April | From 15 April |", "|---|---|---|---|---|"]
    early, late = test["pub"] < apr, test["pub"] >= apr
    for n in names + ["total"]:
        m = np.ones(len(test), bool) if n == "total" else (test["grp"] == n).to_numpy()
        lines.append(f"| {n} | {int(m.sum()):,} | {test['has_nvd'][m].mean():.1%} | {test['has_nvd'][m & early].mean():.1%} (n = {int((m & early).sum()):,}) "
                     f"| {test['has_nvd'][m & late].mean():.1%} (n = {int((m & late).sum()):,}) |")
    lines.append(f"\nOf the test CVEs with an NVD vector, {(test.loc[test['has_nvd'], 'pub'] >= apr).mean():.1%} were published from 15 April on; of the whole test set, {late.mean():.1%}.\n")

    band = np.asarray(nr.Encoded(test, "y_").band)
    lines += ["## B. Share of CNA labels rated High or Critical\n", "| Source | With an NVD vector | Without an NVD vector |", "|---|---|---|"]
    for n in names + ["non-derived total"]:
        m = (test["label_type"] != "derived").to_numpy() if n == "non-derived total" else (test["grp"] == n).to_numpy()
        a, b = m & test["has_nvd"].to_numpy(), m & ~test["has_nvd"].to_numpy()
        lines.append(f"| {n} | {np.mean(band[a] >= 3):.1%} (n = {int(a.sum()):,}) | {np.mean(band[b] >= 3):.1%} (n = {int(b.sum()):,}) |")

    d = df[df["has_nvd"]].reset_index(drop=True)
    ref = {k: np.array([nvd[c][0][k] for c in d["cve_id"]]) for k in ["AV", "AC", "PR", "UI", "C", "I", "A", "S"]}
    same = nr.match(nr.shared_from_v4(d, "y_"), ref).all(1)
    periods = [("before 2026", d["pub"] < CUTOFF), ("2026-01-01 to 04-14", (d["pub"] >= CUTOFF) & (d["pub"] < apr)), ("from 2026-04-15", d["pub"] >= apr)]
    lines += ["\n## C. Share of CNA v4.0 labels identical to the NVD on all seven shared items (all CVEs with an NVD v3.1 vector)\n", "| Period | " + " | ".join(names) + " |", "|---|" + "---|" * len(names)]
    for pn, pm in periods:
        cells = []
        for n in names:
            m = (pm & (d["grp"] == n)).to_numpy()
            cells.append(f"{same[m].mean():.1%} (n = {int(m.sum()):,})")
        lines.append(f"| {pn} | " + " | ".join(cells) + " |")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
