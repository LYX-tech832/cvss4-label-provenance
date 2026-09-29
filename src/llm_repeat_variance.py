"""大模型基线的重复运行稳定性（CPU）：同一批 CVE、同样设置调用多次，看结果随采样波动多大。

读取主运行（2,000 条）和 run_autocvss_baseline.py --run_tag repN 的重复运行（同一批 200 条），在重复运行覆盖的 CVE 上：
  - 每次运行的指标（整体 + 按标签类型），以及跨运行的均值 ± 标准差；
  - 原始答案的一致率：同一（CVE, 指标）在各次运行中答案完全相同的比例（按指标）；整条向量、严重性等级完全一致的比例。
    另给"两两一致率"（每两次运行之间的一致率取平均），运行次数不同的两组设置（如默认温度 3 次、温度 0 两次）用它比较。
输出：results/autocvss_baseline/repeat_variance_<主运行目录名>.md
用法：python src/llm_repeat_variance.py [--main_dir results/autocvss_baseline/deepseek-v4-pro_DTD_s0]
"""

import argparse
import json
import sys
from itertools import combinations
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import M40, evaluate, load, source_type_map, to_vector, v4_score  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TYPES = ["derived", "independent", "v4_only", "other"]
COLS = [("mean_macro_f1", "meanF1"), ("exact_match", "exact"), ("score_mae", "MAE"), ("band_acc", "band"),
        ("under_rate", "under"), ("hc_recall", "HC-rec")]


def raw_labels(run_dir):
    rows = [json.loads(line) for line in (run_dir / "raw.jsonl").read_text(encoding="utf-8").splitlines()]
    return {(r["cve_id"], r["metric"]): r["label"] for r in rows}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--main_dir", default=str(ROOT / "results" / "autocvss_baseline" / "deepseek-v4-pro_DTD_s0"))
    args = ap.parse_args()
    main_dir = Path(args.main_dir)
    reps = sorted(main_dir.parent.glob(main_dir.name + "_rep*"))
    if not reps:
        sys.exit("没有找到重复运行（--run_tag repN 的输出目录）")
    runs = {"主运行": main_dir, **{d.name.rsplit("_", 1)[1]: d for d in reps}}
    cves = pd.read_parquet(reps[0] / "predictions.parquet")["cve_id"]

    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    test = df.set_index("cve_id").loc[cves].reset_index()
    preds = {n: pd.read_parquet(d / "predictions.parquet").set_index("cve_id").loc[cves].reset_index() for n, d in runs.items()}
    raws = {n: raw_labels(d) for n, d in runs.items()}

    info = json.loads((reps[0] / "results.json").read_text(encoding="utf-8"))
    temp = info.get("temperature")
    lines = [f"# 大模型基线的重复运行稳定性（同一批 {len(cves)} 条 CVE，{len(runs)} 次运行，自动生成）\n",
             f"- 各次设置完全相同：{info['model']}，AutoCVSS {info['prompt']} 提示，思考模式 {info.get('thinking')}，"
             f"采样温度 {'接口默认值（AutoCVSS 未设置）' if temp is None else temp}",
             "- 标准差只反映大模型采样的随机性，不包括\"换一批 CVE\"带来的抽样误差\n",
             "## 指标：各次运行与均值 ± 标准差\n",
             "| 范围 | 运行 | " + " | ".join(c for _, c in COLS) + " |", "|---|---|" + "---|" * len(COLS)]
    for scope in ["整体"] + TYPES:
        m = np.ones(len(test), bool) if scope == "整体" else (test["label_type"] == scope).values
        res = {n: evaluate(test[m].reset_index(drop=True), p[m].reset_index(drop=True)) for n, p in preds.items()}
        for n, r in res.items():
            lines.append(f"| {scope}（n={m.sum()}） | {n} | " + " | ".join(f"{r[k]:.3f}" for k, _ in COLS) + " |")
        lines.append(f"| {scope}（n={m.sum()}） | **均值 ± 标准差** | " + " | ".join(
            f"{np.mean([r[k] for r in res.values()]):.3f} ± {np.std([r[k] for r in res.values()], ddof=1):.3f}" for k, _ in COLS) + " |")

    lines += ["\n## 原始答案的一致率\n", "同一（CVE, 指标）在所有运行中答案完全相同的比例（DONT_KNOW 也算一种答案）：\n",
              "| 指标 | " + " | ".join(M40) + " | 平均 |", "|---|" + "---|" * (len(M40) + 1)]
    pairs = list(combinations(runs, 2))
    agree = {k: np.mean([len({raws[n].get((c, k)) for n in runs}) == 1 for c in cves]) for k in M40}
    pair_agree = {k: np.mean([np.mean([raws[a].get((c, k)) == raws[b].get((c, k)) for c in cves]) for a, b in pairs]) for k in M40}
    lines.append(f"| 所有 {len(runs)} 次都相同 | " + " | ".join(f"{agree[k]:.3f}" for k in M40) + f" | {np.mean(list(agree.values())):.3f} |")
    lines.append("| 两两一致率（平均） | " + " | ".join(f"{pair_agree[k]:.3f}" for k in M40) + f" | {np.mean(list(pair_agree.values())):.3f} |")
    dk = {n: round(float(np.mean([raws[n].get((c, k)) in (None, "DONT_KNOW") for c in cves for k in M40])), 3) for n in runs}
    vec = {n: p[M40].apply(to_vector, axis=1) for n, p in preds.items()}
    same_vec = np.mean([len({vec[n].iloc[i] for n in runs}) == 1 for i in range(len(cves))])
    pair_vec = np.mean([np.mean(vec[a].values == vec[b].values) for a, b in pairs])
    band = {n: [v4_score(v)[1] for v in vec[n]] for n in runs}
    same_band = np.mean([len({band[n][i] for n in runs}) == 1 for i in range(len(cves))])
    pair_band = np.mean([np.mean([x == y for x, y in zip(band[a], band[b])]) for a, b in pairs])
    lines += ["", f"- 整条向量完全相同的 CVE 比例：所有 {len(runs)} 次都相同 {same_vec:.3f}；两两平均 {pair_vec:.3f}",
              f"- 严重性等级完全相同的 CVE 比例：所有 {len(runs)} 次都相同 {same_band:.3f}；两两平均 {pair_band:.3f}",
              f"- 各次运行回答 DONT_KNOW（或调用失败）的比例：{dk}"]
    out = main_dir.parent / f"repeat_variance_{main_dir.name}.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\n已写入 {out}")


if __name__ == "__main__":
    main()
