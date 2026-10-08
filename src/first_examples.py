"""第四轮审稿意见 M7：用 FIRST 官方的 CVSS v4.0 示例作为独立的参照，检验规则 R（CPU，几秒）。

FIRST 的示例文档（https://www.first.org/cvss/v4.0/examples，文档版本 1.8，2026-10-03 访问）给出了若干漏洞
由 FIRST CVSS 特别兴趣组评定的 v3.x 向量和 v4.0 向量。这里把规则 R 用在 FIRST 的 v3.x 向量上，
看它能否得到 FIRST 自己给出的 v4.0 基础向量。样本很小、且是为说明新指标而挑选的，只作描述性的参照。

用法：
  python src/first_examples.py                      # 读 data/external/first_v4_examples.csv
  python src/first_examples.py --html 保存的页面.html  # 从保存的页面重新生成这个 csv（每个示例取第一个 v3.x 向量和第一个 v4.0 向量）
输出：results/review_checks/summary11.md
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
    ap.add_argument("--html", help="保存的 FIRST 示例页面；给出时重新生成 csv")
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
    lines = ["# FIRST 官方 v4.0 示例上的规则 R（自动生成）\n",
             f"FIRST 示例文档 1.8 版中同时给出 v3.x 向量和 v4.0 向量的示例：{len(df)} 个（其中 v3.0 向量 {int((df['v3_version'] == '3.0').sum())} 个）。"
             "每个示例取第一个 v3.x 向量和第一个 v4.0 向量（后面的向量是文档讨论的变体场景）。\n",
             "| 范围 | n | 规则 R 得到完全相同的向量 | 严重性等级相同 | 规则 R 的等级更低 / 更高 |", "|---|---|---|---|---|"]
    for name, m in [("全部示例", df["section"] != ""), ("不含\"新指标\"一节", df["section"] != "new_metric"), ("\"新指标\"一节", df["section"] == "new_metric")]:
        d = df[m]
        lines.append(f"| {name} | {len(d)} | {int(d['exact'].sum())}（{d['exact'].mean():.1%}） | {int((d['cmp'] == 0).sum())}（{(d['cmp'] == 0).mean():.1%}） | {int((d['cmp'] < 0).sum())} / {int((d['cmp'] > 0).sum())} |")
    lines += ["\n## 逐指标：规则 R 与 FIRST 的 v4.0 向量一致的示例数\n", "| " + " | ".join(M40) + " |", "|" + "---|" * len(M40),
              "| " + " | ".join(str(sum(c[k] == t[k] for c, t in zip(conv, true))) for k in M40) + f" |\n\n（共 {len(df)} 个示例。）"]
    at = sum(t["AT"] == "P" for t in true)
    ua = sum(t["UI"] == "A" for t in true)
    lines += ["\n## 规则 R 无法产生的取值\n",
              f"FIRST 的 v4.0 向量中 AT:P 有 {at} 个（{at / len(df):.1%}），UI:A 有 {ua} 个（{ua / len(df):.1%}）；"
              f"至少含其中之一的示例 {sum(t['AT'] == 'P' or t['UI'] == 'A' for t in true)} 个。",
              f"规则 R 把 AC 原样保留；FIRST 把 v3.x 的 AC:H 改为 AC:L 的示例：{sum(c['AC'] == 'H' and t['AC'] == 'L' for c, t in zip(conv, true))} 个"
              f"（v3.x 为 AC:H 的共 {sum(c['AC'] == 'H' for c in conv)} 个）。",
              f"v3.x 为 S:C 的示例 {sum('S:C' in v for v in df['v3_base'])} 个，其中规则 R 的 VC/VI/VA/SC/SI/SA 六项与 FIRST 全部一致的："
              f"{sum('S:C' in v and all(c[k] == t[k] for k in ['VC', 'VI', 'VA', 'SC', 'SI', 'SA']) for v, c, t in zip(df['v3_base'], conv, true))} 个。",
              "\n## 明细\n", "| CVE | 节 | v3.x 向量 | FIRST 的 v4.0 向量 | 规则 R | 相同 | 等级（FIRST / 规则 R） |", "|---|---|---|---|---|---|---|"]
    for _, r in df.iterrows():
        lines.append(f"| {r['cve_id']} | {r['section']} | {r['v3_base']} | {r['v4_base']} | {r['r_base']} | {'是' if r['exact'] else '否'} | {r['band_true']} / {r['band_r']} |")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:22]))


if __name__ == "__main__":
    main()
