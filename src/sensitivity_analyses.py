"""敏感性分析（CPU）。

① 来源分型阈值：FD_oos 阈值取 0.80 / 0.90（主设定）/ 0.95（都用 2026 年以前的数据），另加"近期窗口"分型
   （只用 2025 年的数据计算 FD_oos，阈值 0.95）。在每种分型下重算：
   - 评测虚高：T2 TF-IDF+LR、T1 规则 R 在"全部测试集"与"去掉 derived"上的差别；
   - 大模型对比：同一批 2,000 条 CVE 上，derived 与非 derived 两组里各方法的表现。
② 分组宏 F1 的口径：evaluate() 用完整标签集（某类在真实和预测里都没出现也记 0 分）；
   对照口径用 sklearn 默认（只算真实或预测中出现过的类别）。看两种口径下结论是否改变。
输出：results/sensitivity/summary.md
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import CUTOFF, M40, evaluate, load  # noqa: E402
from cvss_utils import V40_METRICS  # noqa: E402
from label_provenance import analyse, collect  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
PRED = ROOT / "results" / "baselines_v0" / "predictions"
OUT = ROOT / "results" / "sensitivity"
LLM_DIR = ROOT / "results" / "autocvss_baseline" / "deepseek-v4-pro_DTD_s0"
TYPES = ["derived", "independent", "v4_only", "other"]


def mean_f1(true_df, pred_df, full_labels=True):
    vals = []
    for k in M40:
        t, p = true_df["y_" + k].values, pred_df[k].values
        vals.append(f1_score(t, p, average="macro", labels=V40_METRICS[k] if full_labels else None, zero_division=0))
    return float(np.mean(vals))


def aligned(path, ids):
    return pd.read_parquet(path).set_index("cve_id").loc[ids].reset_index()


def row(name, t, p):
    r = evaluate(t.reset_index(drop=True), p.reset_index(drop=True))
    return (f"| {name}（n={len(t):,}） | {r['mean_macro_f1']:.3f} | {mean_f1(t, p, False):.3f} | {r['exact_match']:.3f} "
            f"| {r['band_acc']:.3f} | {r['under_rate']:.3f} |")


def main():
    df = load()
    types = json.loads((ROOT / "results" / "label_provenance" / "source_types.json").read_text(encoding="utf-8"))
    fd_pre = {s: v["FD_oos_pre2026"] for s, v in types.items() if "FD_oos_pre2026" in v}
    start25 = CUTOFF - pd.DateOffset(years=1)
    pairs25 = collect(df[(df["pub"] >= start25) & (df["pub"] < CUTOFF)])
    fd_25 = {s: analyse(p)["FD_oos"] for s, p in pairs25.items() if len(p) >= 100}
    typings = {"阈值 0.80": {s for s, v in fd_pre.items() if v >= 0.80},
               "阈值 0.90（主设定）": {s for s, v in fd_pre.items() if v >= 0.90},
               "阈值 0.95": {s for s, v in fd_pre.items() if v >= 0.95},
               "近期窗口（2025 年数据，阈值 0.95）": {s for s, v in fd_25.items() if v >= 0.95}}

    lines = ["# 敏感性分析（自动生成）\n", "## ① 来源分型阈值\n",
             "各来源的样本外函数依赖度 FD_oos（2026 年以前全部数据 / 只用 2025 年数据；对数 ≥100 的来源）：\n",
             "| 来源 | FD_oos（2026 年以前） | FD_oos（2025 年） |", "|---|---|---|"]
    for s in sorted(set(fd_pre) | set(fd_25), key=lambda s: -fd_pre.get(s, fd_25.get(s, 0))):
        a, b = fd_pre.get(s), fd_25.get(s)
        lines.append(f"| {s} | {'—' if a is None else f'{a:.1%}'} | {'—' if b is None else f'{b:.1%}'} |")
    lines += ["", "各分型下判为 derived 的来源：" + "；".join(f"{k}：{'、'.join(sorted(v)) or '无'}" for k, v in typings.items()), ""]

    t2 = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    t1 = df[df["has_v31"] & (df["pub"] >= CUTOFF)].reset_index(drop=True)
    tfidf, rule = aligned(PRED / "T2_temporal_tfidf_lr.parquet", t2["cve_id"]), aligned(PRED / "T1_temporal_rule_R.parquet", t1["cve_id"])
    lines += ["### 评测虚高：全部测试集 vs 去掉 derived\n",
              "| 分型 / 设定 / 范围 | 平均宏 F1（完整标签集） | 平均宏 F1（sklearn 默认） | 整向量全对 | 等级准确率 | 低估率 |",
              "|---|---|---|---|---|---|"]
    lines.append(row("T2 TF-IDF+LR，全部", t2, tfidf))
    lines.append(row("T1 规则 R，全部", t1, rule))
    for name, der in typings.items():
        if not der:
            lines.append(f"| {name}：没有来源被判为 derived，无法区分 | | | | | |")
            continue
        m2, m1 = ~t2["source"].isin(der).values, ~t1["source"].isin(der).values
        lines.append(row(f"{name}，T2 TF-IDF+LR，去掉 derived", t2[m2], tfidf[m2]))
        lines.append(row(f"{name}，T1 规则 R，去掉 derived", t1[m1], rule[m1]))

    # 大模型对比（同一批 2,000 条）：derived vs 非 derived
    llm = pd.read_parquet(LLM_DIR / "predictions.parquet")
    s = df.set_index("cve_id").loc[llm["cve_id"]].reset_index()
    # 每个方法是一组预测（多个种子时指标按种子取平均）；DeBERTa 用 W4 选定配置的全部种子，与表 9 同一口径
    w4 = sorted((ROOT / "results/encoder").glob("T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s[0-9]/pred_latent.parquet"))
    methods = {"AutoCVSS + DeepSeek": [llm.set_index("cve_id").loc[s["cve_id"]].reset_index()],
               "TF-IDF+LR": [aligned(PRED / "T2_temporal_tfidf_lr.parquet", s["cve_id"])],
               "TF-IDF+LR（只用描述）": [aligned(ROOT / "results/ablation_desc_only/T2_temporal_tfidf_lr_desc_only.parquet", s["cve_id"])],
               f"DeBERTa+辅助（W4，{len(w4)} 个种子）": [aligned(f, s["cve_id"]) for f in w4]}
    avg = lambda ps, fn: float(np.mean([fn(p) for p in ps]))  # noqa: E731
    lines += ["\n### 大模型对比（同一批 2,000 条）：各分型下 derived 与非 derived 两组\n",
              "每格为 平均宏 F1（完整标签集）/ 平均宏 F1（sklearn 默认）/ 等级准确率\n",
              "| 分型 | 组 | " + " | ".join(methods) + " |", "|---|---|" + "---|" * len(methods)]
    for name, der in typings.items():
        for grp, m in [("derived", s["source"].isin(der).values), ("非 derived", ~s["source"].isin(der).values)]:
            if m.sum() < 30:
                continue
            cells = []
            for ps in methods.values():
                rs = [evaluate(s[m].reset_index(drop=True), p[m].reset_index(drop=True)) for p in ps]
                cells.append(f"{np.mean([r['mean_macro_f1'] for r in rs]):.3f} / {avg(ps, lambda p: mean_f1(s[m], p[m], False)):.3f} / "
                             f"{np.mean([r['band_acc'] for r in rs]):.3f}")
            lines.append(f"| {name} | {grp}（n={m.sum()}） | " + " | ".join(cells) + " |")

    # ② 口径：主设定的四个标签类型，看方法排名是否改变
    s["label_type"] = s["source"].map({k: v["type"] for k, v in types.items()}).fillna("other")
    lines += ["\n## ② 分组宏 F1 的口径（主设定分型，同一批 2,000 条）\n",
              "| 标签类型 | 口径 | " + " | ".join(methods) + " | 排名（高→低） |", "|---|---|" + "---|" * (len(methods) + 1)]
    for t in TYPES:
        m = (s["label_type"] == t).values
        for full, lab in [(True, "完整标签集"), (False, "sklearn 默认")]:
            vals = {n: avg(ps, lambda p: mean_f1(s[m], p[m], full)) for n, ps in methods.items()}
            rank = " > ".join(n for n, _ in sorted(vals.items(), key=lambda kv: -kv[1]))
            lines.append(f"| {t}（n={m.sum()}） | {lab} | " + " | ".join(f"{v:.3f}" for v in vals.values()) + f" | {rank} |")

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
