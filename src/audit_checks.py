"""自查（10-03 夜，用户批准的"反方自查"第 1 步）：对核心结论逐条找最简单的替代解释，这里补算此前没做的对照（CPU，约 20 分钟）。

A. "VulDB 的标签更容易预测"会不会只是因为它的训练标签最多？——每个来源只用 1,000 条自己的 2026 年前的 v4.0 标签训练
   TF-IDF + LR（随机抽 5 次），在该来源 2026 年的标签上测试；VulDB 另外用同样 1,000 条的 v3.1 标签再做一遍。
B. 排名随标签来源改变是否只有"大模型对 TF-IDF、宏 F1"这一个例子？——时间划分完整测试集上，直接预测 v4.0 的模型与
   不用任何 v4.0 标签的流水线（预测 v3.1 再按规则 R 换算）在"全部"与"非 derived"上的配对差值（对测试 CVE 重抽样 1,000 次）。
   流水线的逐条预测此前没有保存，这里重算并存到 results/pipeline_baseline/predictions/。
C. "换算做法随时间变化"（VulnCheck 的规则一致率上升）会不会是回填旧漏洞造成的构成变化？——VulnCheck 各季度的规则一致率，
   按 CVE 编号年份是否比发布年份早两年以上分开。
D. 2,000 条大模型样本上所有方法两两比较：合并与非 derived 的差值符号是否相反（类型内重抽样 1,000 次）。
输出：results/review_checks/summary12.md
"""

import sys
from itertools import combinations
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import cohen_kappa_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded, fast_scores  # noqa: E402
from baselines_v0 import CUTOFF, M31, M40, load, source_type_map  # noqa: E402
from pilot_transfer import v31_pool  # noqa: E402
from pipeline_baseline import convert, stage1  # noqa: E402
from review_checks9 import band31, fit_predict  # noqa: E402
from rq1_stats import rule_convert  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
PRED = ROOT / "results" / "baselines_v0" / "predictions"
PIPE = ROOT / "results" / "pipeline_baseline" / "predictions"
LLM = ROOT / "results" / "autocvss_baseline"
OUT = ROOT / "results" / "review_checks" / "summary12.md"
rng = np.random.default_rng(0)
KEYS = ("mean_macro_f1", "band_acc", "under_rate")


def part_a(df, lines):
    lines += ["## A. 各来源只用自己的 1,000 条标签训练（TF-IDF + LR；5 次随机抽样的平均），在该来源 2026 年的标签上测试\n",
              "| 来源 | 2026 年前的 v4.0 标签 | 测试标签 | 标签 | 基率 | 等级准确率 | κ | 平均宏 F1 |", "|---|---|---|---|---|---|---|---|"]
    for src in ["VulDB", "VulnCheck", "GitHub_M"]:
        d = df[df["source"] == src]
        tr_all, te = d[d["pub"] < CUTOFF], d[d["pub"] >= CUTOFF].reset_index(drop=True)
        t = Encoded(te, "y_")
        idx = np.arange(len(te))
        versions = [("v4.0", None)] + ([("v3.1", "x31_")] if src == "VulDB" else [])
        for ver, pre in versions:
            accs, kaps, f1s = [], [], []
            for draw in range(5):
                tr = tr_all.sample(1000, random_state=draw)
                if pre is None:
                    p = fit_predict(tr["text"], te["text"], {k: tr["y_" + k].values for k in M40})
                    e = Encoded(p.assign(cve_id=te["cve_id"]))
                    tb, pb = t.band, e.band
                    f1s.append(fast_scores(t, e, idx)["mean_macro_f1"])
                else:
                    from review_checks9 import macro_f1
                    from cvss_utils import V31_METRICS
                    p = fit_predict(tr["text"], te["text"], {k: tr[pre + k].values for k in M31})
                    tb, pb = band31(te, pre), band31(p.add_prefix("p_"), "p_")
                    f1s.append(macro_f1(te[[pre + k for k in M31]].set_axis(M31, axis=1), p, V31_METRICS))
                accs.append((tb == pb).mean())
                kaps.append(cohen_kappa_score(tb, pb))
            base = np.bincount(tb[tb >= 0]).max() / len(tb)
            lines.append(f"| {src} | {len(tr_all):,} | {len(te):,} | {ver} | {base:.3f} | {np.mean(accs):.3f} | {np.mean(kaps):.3f} | {np.mean(f1s):.3f} |")
    lines.append("\n（VulDB 的 v3.1 一行：同样的 1,000 条 CVE，标签换成它自己的 v3.1 向量，宏 F1 在 8 个 v3.1 指标上平均。）")


def part_b(df, lines):
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    PIPE.mkdir(parents=True, exist_ok=True)
    f_r, f_n = PIPE / "T2_temporal_pipeline_rule_R.parquet", PIPE / "T2_temporal_pipeline_scsisa_N.parquet"
    if not (f_r.exists() and f_n.exists()):
        v31 = stage1(v31_pool(before_cutoff=True), list(test["text"]))
        convert(v31, True).assign(cve_id=test["cve_id"]).to_parquet(f_r, index=False)
        convert(v31, False).assign(cve_id=test["cve_id"]).to_parquet(f_n, index=False)
    ids = test["cve_id"]
    t = Encoded(test, "y_")

    def enc(path):
        return Encoded(pd.read_parquet(path).set_index("cve_id").loc[ids].reset_index())
    es = {"TF-IDF": [enc(PRED / "T2_temporal_tfidf_lr.parquet")], "流水线（规则 R）": [enc(f_r)], "流水线（SC/SI/SA=N）": [enc(f_n)],
          "DeBERTa": [enc(ENC / f"T2_temporal_deberta-v3-base_none_e25_cwinv_sqrt_s{s}" / "pred_latent.parquet") for s in range(5)],
          "DeBERTa+辅助": [enc(ENC / f"T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s{s}" / "pred_latent.parquet") for s in range(5)]}
    nd = (test["label_type"] != "derived").to_numpy()

    def sc(name, ix):
        rs = [fast_scores(t, e, ix) for e in es[name]]
        return np.array([np.mean([r[k] for r in rs]) for k in KEYS])
    lines += ["\n## B. 完整测试集上，直接预测 v4.0 的模型 − 不用 v4.0 标签的流水线（配对 bootstrap，1,000 次）\n",
              "流水线点估计（核对用，应与表 7 一致）：" + "；".join(
                  f"{n} 全部 {sc(n, np.arange(len(test)))[0]:.3f} / {sc(n, np.arange(len(test)))[1]:.3f}，非 derived {sc(n, np.flatnonzero(nd))[0]:.3f} / {sc(n, np.flatnonzero(nd))[1]:.3f}"
                  for n in ["流水线（规则 R）", "流水线（SC/SI/SA=N）"]) + "（平均宏 F1 / 等级准确率）。\n",
              "| A − B | 范围 | 平均宏 F1 | 等级准确率 | 低估率 |", "|---|---|---|---|---|"]
    for a, b in [("TF-IDF", "流水线（规则 R）"), ("DeBERTa", "流水线（规则 R）"), ("DeBERTa+辅助", "流水线（规则 R）"), ("DeBERTa+辅助", "流水线（SC/SI/SA=N）")]:
        for name, idx in [("全部", np.arange(len(test))), ("非 derived", np.flatnonzero(nd))]:
            d = sc(a, idx) - sc(b, idx)
            bs = np.array([sc(a, ix) - sc(b, ix) for ix in (rng.choice(idx, size=len(idx), replace=True) for _ in range(1000))])
            lines.append(f"| {a} − {b} | {name} | " + " | ".join(f"{d[j]:+.3f} [{np.percentile(bs[:, j], 2.5):+.3f}, {np.percentile(bs[:, j], 97.5):+.3f}]" for j in range(3)) + " |")


def part_c(df, lines):
    d = df[(df["source"] == "VulnCheck") & df["has_v31"]].copy()
    conv = [rule_convert({k: r["x31_" + k] for k in M31}) for _, r in d.iterrows()]
    d["agree"] = [all(c[k] == r["y_" + k] for k in M40) for c, (_, r) in zip(conv, d.iterrows())]
    d["q"] = d["pub"].dt.tz_localize(None).dt.to_period("Q").astype(str)
    d["old"] = d["cve_id"].str.extract(r"CVE-(\d{4})-")[0].astype(int) <= d["pub"].dt.year - 2
    lines += ["\n## C. VulnCheck 各季度的规则 R 一致率：新漏洞与回填的旧漏洞（编号年份比发布年份早两年以上）分开\n",
              "| 季度 | 全部：n / 一致率 | 新漏洞：n / 一致率 | 回填：n / 一致率 |", "|---|---|---|---|"]
    for q, g in d.groupby("q"):
        if len(g) < 30:
            continue
        cell = lambda x: f"{len(x):,} / {x['agree'].mean():.1%}" if len(x) else "0 / –"  # noqa: E731
        lines.append(f"| {q} | {cell(g)} | {cell(g[~g['old']])} | {cell(g[g['old']])} |")


def part_d(df, lines):
    main = LLM / "deepseek-v4-pro_DTD_s0" / "predictions.parquet"
    ids = pd.read_parquet(main)["cve_id"]
    truth = df.set_index("cve_id").loc[ids].reset_index()
    t = Encoded(truth, "y_")

    def enc(path):
        return Encoded(pd.read_parquet(path).set_index("cve_id").loc[ids].reset_index())
    es = {"DeepSeek": [enc(main)], "Qwen3-8B": [enc(LLM / "Qwen3-8B_DTD_s0" / "predictions.parquet")],
          "多数类": [enc(PRED / "T2_temporal_majority.parquet")], "TF-IDF": [enc(PRED / "T2_temporal_tfidf_lr.parquet")],
          "流水线（规则 R）": [enc(PIPE / "T2_temporal_pipeline_rule_R.parquet")],
          "DeBERTa": [enc(ENC / f"T2_temporal_deberta-v3-base_none_e25_cwinv_sqrt_s{s}" / "pred_latent.parquet") for s in range(5)],
          "DeBERTa+辅助": [enc(ENC / f"T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s{s}" / "pred_latent.parquet") for s in range(5)]}
    lt = truth["label_type"].to_numpy()
    types = ["derived", "independent", "v4_only", "other"]
    strata = {ty: np.flatnonzero(lt == ty) for ty in types}

    def sc(ix):
        return {n: np.array([np.mean([fast_scores(t, e, ix)[k] for e in ee]) for k in KEYS[:2]]) for n, ee in es.items()}
    scopes = {"pooled": types, "nd": types[1:]}
    point = {s: sc(np.concatenate([strata[ty] for ty in tys])) for s, tys in scopes.items()}
    boots = []
    for _ in range(1000):
        res = {ty: rng.choice(ix, size=len(ix), replace=True) for ty, ix in strata.items()}  # 两个口径用同一次重抽样
        boots.append({s: sc(np.concatenate([res[ty] for ty in tys])) for s, tys in scopes.items()})
    lines += ["\n## D. 2,000 条样本上所有方法两两比较：合并与非 derived 的差值符号是否相反\n",
              "| A − B | 指标 | 合并 [95%] | 非 derived [95%] | 符号相反 | 两个区间都不含 0 |", "|---|---|---|---|---|---|"]
    n_pairs = n_flip = n_sig = 0
    for a, b in combinations(es, 2):
        for j, key in enumerate(["平均宏 F1", "等级准确率"]):
            n_pairs += 1
            vals = {}
            for s in scopes:
                d = point[s][a][j] - point[s][b][j]
                ci = np.percentile([bb[s][a][j] - bb[s][b][j] for bb in boots], [2.5, 97.5])
                vals[s] = (d, ci)
            flip = vals["pooled"][0] * vals["nd"][0] < 0
            sig = flip and all(ci[0] * ci[1] > 0 for _, ci in vals.values())
            n_flip += flip
            n_sig += sig
            if flip:
                lines.append(f"| {a} − {b} | {key} | " + " | ".join(f"{vals[s][0]:+.3f} [{vals[s][1][0]:+.3f}, {vals[s][1][1]:+.3f}]" for s in scopes) + f" | 是 | {'是' if sig else '否'} |")
    lines.append(f"\n共 {n_pairs} 个（方法对 × 指标）；符号相反的 {n_flip} 个，其中两个区间都不含 0 的 {n_sig} 个。只列出符号相反的。")


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    lines = ["# 自查补算的对照（自动生成）\n"]
    for step in (part_a, part_b, part_c, part_d):
        step(df, lines)
        OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
