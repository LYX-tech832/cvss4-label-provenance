"""Rule R checked against FIRST's official CVSS v4.0 examples as an independent reference (CPU, seconds).

FIRST's examples document (https://www.first.org/cvss/v4.0/examples, document version 1.8, accessed 3 October 2026) gives, for a number
of vulnerabilities, the v3.x and v4.0 vectors assessed by the FIRST CVSS Special Interest Group. This script applies rule R to FIRST's
v3.x vectors and checks whether it yields FIRST's own v4.0 base vector. The sample is small and was chosen to illustrate the new
metrics, so it serves only as a descriptive reference.

Usage:
  python src/first_examples.py                       # reads data/external/first_v4_examples.csv
  python src/first_examples.py --html saved_page.html  # rebuilds this csv from the saved page (first v3.x and first v4.0 vector of each example)
Output: results/review_checks/summary11.md
"""

import argparse
import html
import re
import sys
from pathlib import Path

import pandas as pd
from cvss import CVSS4

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cvss_utils import V40_METRICS  # noqa: E402
from rq1_stats import rule_convert  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CSV = ROOT / "data" / "external" / "first_v4_examples.csv"
OUT = ROOT / "results" / "review_checks" / "summary11.md"
M40 = list(V40_METRICS)
M3 = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
SECTIONS = {"New-metric-coverage": "new_metric", "CISA-KEV-Examples": "kev", "Classic-Examples": "classic", "Common-Vulnerabilities-Classes": "class"}


def parse_page(path):
    t = Path(path).read_text(encoding="utf-8", errors="replace")
    heads = [(h.start(), h.group(1)) for h in re.finditer(r'<h[1-4] id="([^"]*)"', t)]
    rows, section = [], ""
    for i, (pos, hid) in enumerate(heads):
        section = SECTIONS.get(hid, section)
        cve = re.search(r"CVE-\d{4}-\d+", hid)
        if not cve:
            continue
        seg = html.unescape(re.sub(r"<[^>]+>", " ", t[pos:heads[i + 1][0] if i + 1 < len(heads) else len(t)]))
        v3 = re.search(r"CVSS:3\.[01]/[A-Za-z:/]+", seg)
        v4 = re.search(r"CVSS:4\.0/[A-Za-z:/]+", seg)
        if not (v3 and v4):
            continue
        d3 = dict(p.split(":") for p in v3.group(0).split("/")[1:])
        d4 = dict(p.split(":") for p in v4.group(0).split("/")[1:])
        rows.append({"cve_id": cve.group(0), "section": section, "v3_version": v3.group(0)[5:8],
                     "v3_base": "/".join(f"{k}:{d3[k]}" for k in M3), "v4_base": "/".join(f"{k}:{d4[k]}" for k in M40)})
    return pd.DataFrame(rows)


def band(vec):
    return CVSS4("CVSS:4.0/" + vec).severity


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--html", help="saved FIRST examples page; if given, the csv is rebuilt")
    args = ap.parse_args()
    if args.html:
        CSV.parent.mkdir(parents=True, exist_ok=True)
        parse_page(args.html).to_csv(CSV, index=False)
    df = pd.read_csv(CSV, dtype=str)
    order = ["None", "Low", "Medium", "High", "Critical"]
    conv = [rule_convert(dict(p.split(":") for p in v.split("/"))) for v in df["v3_base"]]
    df["r_base"] = ["/".join(f"{k}:{c[k]}" for k in M40) for c in conv]
    true = [dict(p.split(":") for p in v.split("/")) for v in df["v4_base"]]
    df["exact"] = df["r_base"] == df["v4_base"]
    df["band_true"], df["band_r"] = df["v4_base"].map(band), df["r_base"].map(band)
    df["cmp"] = [order.index(r) - order.index(t) for r, t in zip(df["band_r"], df["band_true"])]
    lines = ["# Rule R on FIRST's official v4.0 examples (generated automatically)\n",
             f"Examples in version 1.8 of FIRST's examples document with both a v3.x and a v4.0 vector: {len(df)} (of which {int((df['v3_version'] == '3.0').sum())} with a v3.0 vector). "
             "The first v3.x and the first v4.0 vector of each example are used (later vectors are variant scenarios discussed in the document).\n",
             "| Scope | n | Rule R gives the identical vector | Same severity band | Rule R's band lower / higher |", "|---|---|---|---|---|"]
    for name, m in [("all examples", df["section"] != ""), ("without the \"new metrics\" section", df["section"] != "new_metric"), ("\"new metrics\" section", df["section"] == "new_metric")]:
        d = df[m]
        lines.append(f"| {name} | {len(d)} | {int(d['exact'].sum())} ({d['exact'].mean():.1%}) | {int((d['cmp'] == 0).sum())} ({(d['cmp'] == 0).mean():.1%}) | {int((d['cmp'] < 0).sum())} / {int((d['cmp'] > 0).sum())} |")
    lines += ["\n## Per metric: examples where rule R agrees with FIRST's v4.0 vector\n", "| " + " | ".join(M40) + " |", "|" + "---|" * len(M40),
              "| " + " | ".join(str(sum(c[k] == t[k] for c, t in zip(conv, true))) for k in M40) + f" |\n\n({len(df)} examples in total.)"]
    at = sum(t["AT"] == "P" for t in true)
    ua = sum(t["UI"] == "A" for t in true)
    lines += ["\n## Values that rule R cannot produce\n",
              f"FIRST's v4.0 vectors contain AT:P in {at} examples ({at / len(df):.1%}) and UI:A in {ua} ({ua / len(df):.1%}); "
              f"examples with at least one of them: {sum(t['AT'] == 'P' or t['UI'] == 'A' for t in true)}.",
              f"Rule R keeps AC unchanged; examples where FIRST changes v3.x AC:H to AC:L: {sum(c['AC'] == 'H' and t['AC'] == 'L' for c, t in zip(conv, true))} "
              f"(of {sum(c['AC'] == 'H' for c in conv)} with AC:H in v3.x).",
              f"Examples with S:C in v3.x: {sum('S:C' in v for v in df['v3_base'])}; of these, examples where rule R agrees with FIRST on all six of VC/VI/VA/SC/SI/SA: "
              f"{sum('S:C' in v and all(c[k] == t[k] for k in ['VC', 'VI', 'VA', 'SC', 'SI', 'SA']) for v, c, t in zip(df['v3_base'], conv, true))}.",
              "\n## Details\n", "| CVE | Section | v3.x vector | FIRST's v4.0 vector | Rule R | Identical | Band (FIRST / rule R) |", "|---|---|---|---|---|---|---|"]
    for _, r in df.iterrows():
        lines.append(f"| {r['cve_id']} | {r['section']} | {r['v3_base']} | {r['v4_base']} | {r['r_base']} | {'yes' if r['exact'] else 'no'} | {r['band_true']} / {r['band_r']} |")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:22]))


if __name__ == "__main__":
    main()
