"""用 NVD 自己给的 v3.1 评分作为第二个独立评估者（CPU，约 3 分钟；10-04 用户同意先算这一项）。

数据：probe/nvd_v4_records.jsonl（2026-09-25 通过 NVD CVE API 2.0 取得的、带 v4.0 向量的 NVD 记录；
其中来源为 nvd@nist.gov 的 v3.1 向量是 NVD 分析员独立评的）。NVD 几乎不给 v4.0（只有 5 条），
所以只能在两版共有的内容上比较：
  AV、AC、PR 直接比较；UI 比较"是否需要用户交互"（v4.0 的 P/A 都算需要）；
  C/I/A 与 v4.0 的 max(VC, SC)、max(VI, SI)、max(VA, SA) 比较（v3.1 的影响不区分本系统与后续系统）；
  严重性等级：NVD 的 v3.1 等级 对 v4.0 向量的 CVSS-B 等级（两版计分方法不同，只作参照）。
A. 覆盖面。B. 各来源的 CNA 标签与 NVD 的吻合程度。C. 时间划分测试集上，各方法以 NVD 为参照的结果。
D. 大模型样本上，DeepSeek 与监督模型以 NVD 为参照的结果（回应"大模型把 VulDB 的漏洞评得更重，谁更合适"）。
输出：results/review_checks/summary13.md
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from cvss import CVSS3

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded  # noqa: E402
from baselines_v0 import CUTOFF, M31, M40, load, source_type_map  # noqa: E402
from cvss_utils import parse_vector  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
PRED = ROOT / "results" / "baselines_v0" / "predictions"
PIPE = ROOT / "results" / "pipeline_baseline" / "predictions"
LLM = ROOT / "results" / "autocvss_baseline"
OUT = ROOT / "results" / "review_checks" / "summary13.md"
BANDS = ["None", "Low", "Medium", "High", "Critical"]
LEVEL = {"N": 0, "L": 1, "H": 2}
SHARED = ["AV", "AC", "PR", "UI", "C", "I", "A"]
rng = np.random.default_rng(0)


def nvd_vectors():
    out = {}
    with open(ROOT / "probe" / "nvd_v4_records.jsonl", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            vs = [v for s, ty, v in r["v31"] if s == "nvd@nist.gov" and ty == "Primary"]
            if vs:
                p = parse_vector(vs[0], "3.1")
                if p:
                    out[r["id"]] = (p, BANDS.index(CVSS3(vs[0]).severities()[0]))
    return out


def shared_from_v4(frame, prefix):
    """v4.0 向量（标签或预测）→ 与 v3.1 可比的 7 项。"""
    g = lambda k: frame[prefix + k].to_numpy()  # noqa: E731
    mx = lambda a, b: np.where(np.vectorize(LEVEL.get)(a) >= np.vectorize(LEVEL.get)(b), a, b)  # noqa: E731
    return {"AV": g("AV"), "AC": g("AC"), "PR": g("PR"), "UI": np.where(g("UI") == "N", "N", "R"),
            "C": mx(g("VC"), g("SC")), "I": mx(g("VI"), g("SI")), "A": mx(g("VA"), g("SA"))}


def match(v4, ref):
    """每条 CVE 在 7 项上的吻合（0/1 矩阵，列顺序 SHARED）。"""
    return np.column_stack([(v4[k] == ref[k]).astype(float) for k in SHARED])


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    nvd = nvd_vectors()
    df = df[df["cve_id"].isin(nvd)].reset_index(drop=True)
    ref = {k: np.array([nvd[c][0][k] for c in df["cve_id"]]) for k in ["AV", "AC", "PR", "UI", "C", "I", "A", "S"]}
    ref_band = np.array([nvd[c][1] for c in df["cve_id"]])
    full = load()
    lines = ["# NVD 的 v3.1 评分作为第二个独立评估者（自动生成）\n",
             "只比较两版共有的内容：AV、AC、PR；UI 是否需要交互；C/I/A 对 max(V, S)；等级为 NVD 的 v3.1 等级对 v4.0 的 CVSS-B 等级。\n",
             "## A. 覆盖面\n",
             f"带 CNA v4.0 标签的 CVE 共 {len(full):,} 条，其中有 NVD 自评 v3.1 向量的 {len(df):,} 条（{len(df) / len(full):.1%}）。"
             f"时间划分测试集（2026 年发布，{int((full['pub'] >= CUTOFF).sum()):,} 条）里有 {int((df['pub'] >= CUTOFF).sum()):,} 条"
             f"（{(df['pub'] >= CUTOFF).sum() / (full['pub'] >= CUTOFF).sum():.1%}）。\n",
             "| 来源 | v4.0 标签 | 有 NVD v3.1 | 占比 | 其中 2026 年 |", "|---|---|---|---|---|"]
    groups = [("VulDB（derived）", "VulDB"), ("VulnCheck", "VulnCheck"), ("GitHub", "GitHub_M")]
    masks = [(n, (df["source"] == s).to_numpy(), (full["source"] == s).to_numpy()) for n, s in groups]
    masks.append(("其他来源", (~df["source"].isin([s for _, s in groups])).to_numpy(), (~full["source"].isin([s for _, s in groups])).to_numpy()))
    is_test = (df["pub"] >= CUTOFF).to_numpy()
    for n, m, mf in masks:
        lines.append(f"| {n} | {int(mf.sum()):,} | {int(m.sum()):,} | {m.sum() / mf.sum():.1%} | {int((m & is_test).sum()):,} |")

    # B. CNA 标签对 NVD
    truth = shared_from_v4(df, "y_")
    mt = match(truth, ref)
    t_band = Encoded(df, "y_").band
    lines += ["\n## B. 各来源的 CNA v4.0 标签与 NVD 的吻合程度（全部有 NVD v3.1 的 CVE）\n",
              "| 来源 | n | " + " | ".join(SHARED) + " | 7 项全同 | 等级相同 | CNA 更低 / 更高 |", "|---|---|" + "---|" * (len(SHARED) + 3)]
    for n, m, _ in masks + [("全部", np.ones(len(df), bool), None), ("非 derived 合计", (df["label_type"] != "derived").to_numpy(), None)]:
        lines.append(f"| {n} | {int(m.sum()):,} | " + " | ".join(f"{mt[m][:, j].mean():.3f}" for j in range(len(SHARED)))
                     + f" | {mt[m].all(1).mean():.3f} | {(t_band[m] == ref_band[m]).mean():.3f} | {(t_band[m] < ref_band[m]).mean():.3f} / {(t_band[m] > ref_band[m]).mean():.3f} |")
    lines.append("\nNVD 的 v3.1 等级分布对比 CNA 的 v4.0 等级分布（Low / Medium / High / Critical）：")
    for n, m, _ in masks:
        d1 = np.bincount(ref_band[m], minlength=5)[1:] / m.sum()
        d2 = np.bincount(t_band[m], minlength=5)[1:] / m.sum()
        lines.append(f"- {n}：NVD " + " / ".join(f"{x:.2f}" for x in d1) + "；CNA " + " / ".join(f"{x:.2f}" for x in d2))
    dual = df["has_v31"].to_numpy()
    lines += ["\n同一 CNA 的 v3.1 向量与 NVD 的 v3.1 向量完全相同的比例（双版本评分的 CVE）：" + "；".join(
        f"{n} {np.mean([all(r['x31_' + k] == nvd[r['cve_id']][0][k] for k in M31) for _, r in df[m & dual].iterrows()]):.1%}（n = {int((m & dual).sum()):,}）"
        for n, m, _ in masks if (m & dual).sum() >= 30) + "。"]

    # C. 各方法对 NVD（时间划分测试集）
    test = df[is_test].reset_index(drop=True)
    ids = test["cve_id"]
    tref = {k: v[is_test] for k, v in ref.items()}
    tband = ref_band[is_test]
    cna_band = t_band[is_test]

    def frames(paths):
        return [pd.read_parquet(p).set_index("cve_id").loc[ids].reset_index() for p in paths]
    methods = {"TF-IDF + LR": frames([PRED / "T2_temporal_tfidf_lr.parquet"]),
               "流水线（规则 R，不用 v4.0 标签）": frames([PIPE / "T2_temporal_pipeline_rule_R.parquet"]),
               "DeBERTa（25 轮）": frames([ENC / f"T2_temporal_deberta-v3-base_none_e25_cwinv_sqrt_s{s}" / "pred_latent.parquet" for s in range(5)]),
               "DeBERTa + 辅助": frames([ENC / f"T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s{s}" / "pred_latent.parquet" for s in range(5)])}
    per = {}
    for name, fs in methods.items():
        agree = np.mean([match(shared_from_v4(f, ""), tref).mean(1) for f in fs], axis=0)       # 每条 CVE 的 7 项平均吻合
        bands = [Encoded(f).band for f in fs]
        per[name] = {"agree": agree, "band_nvd": np.mean([(b == tband) for b in bands], axis=0), "under_nvd": np.mean([(b < tband) for b in bands], axis=0),
                     "band_cna": np.mean([(b == cna_band) for b in bands], axis=0)}
    nd = (test["label_type"] != "derived").to_numpy()
    lines += ["\n## C. 时间划分测试集上，各方法以 NVD 为参照的结果\n",
              f"测试集里有 NVD v3.1 的 CVE：{len(test):,} 条（derived {int((~nd).sum()):,}，非 derived {int(nd.sum()):,}）。"
              "7 项吻合率 = 预测的 v4.0 向量与 NVD 在 7 项共有内容上的平均吻合；后一列是同一批 CVE 上对 CNA 标签的等级准确率，用于对照。\n",
              "| 范围 | 方法 | 7 项吻合率（对 NVD） | 等级相同（对 NVD） | 比 NVD 低 | 等级准确率（对 CNA 标签） |", "|---|---|---|---|---|---|"]
    scopes = [("全部", np.ones(len(test), bool)), ("derived（VulDB）", ~nd), ("非 derived", nd)]
    for sn, m in scopes:
        for name in methods:
            p = per[name]
            lines.append(f"| {sn}（{int(m.sum()):,}） | {name} | {p['agree'][m].mean():.3f} | {p['band_nvd'][m].mean():.3f} | {p['under_nvd'][m].mean():.3f} | {p['band_cna'][m].mean():.3f} |")
        lines.append(f"| {sn}（{int(m.sum()):,}） | CNA 的 v4.0 标签本身 | {mt[is_test][m].mean():.3f} | {(cna_band[m] == tband[m]).mean():.3f} | {(cna_band[m] < tband[m]).mean():.3f} | — |")
    lines += ["\n配对差值（对测试 CVE 重抽样 1,000 次，95% 区间）：\n", "| A − B | 范围 | 7 项吻合率（对 NVD） | 等级相同（对 NVD） | 等级准确率（对 CNA 标签） |", "|---|---|---|---|---|"]
    for a, b in [("TF-IDF + LR", "流水线（规则 R，不用 v4.0 标签）"), ("DeBERTa + 辅助", "流水线（规则 R，不用 v4.0 标签）"), ("DeBERTa + 辅助", "DeBERTa（25 轮）")]:
        for sn, m in scopes:
            idx = np.flatnonzero(m)
            cells = []
            for key in ("agree", "band_nvd", "band_cna"):
                d = per[a][key] - per[b][key]
                bs = [d[rng.choice(idx, size=len(idx), replace=True)].mean() for _ in range(1000)]
                cells.append(f"{d[idx].mean():+.3f} [{np.percentile(bs, 2.5):+.3f}, {np.percentile(bs, 97.5):+.3f}]")
            lines.append(f"| {a} − {b} | {sn} | " + " | ".join(cells) + " |")

    # D. 大模型样本
    lids = pd.read_parquet(LLM / "deepseek-v4-pro_DTD_s0" / "predictions.parquet")["cve_id"]
    sub = test[test["cve_id"].isin(set(lids))].reset_index(drop=True)
    sref_band = np.array([nvd[c][1] for c in sub["cve_id"]])
    sref = {k: np.array([nvd[c][0][k] for c in sub["cve_id"]]) for k in SHARED}
    s_cna = Encoded(sub, "y_").band

    def sframes(paths):
        return [pd.read_parquet(p).set_index("cve_id").loc[sub["cve_id"]].reset_index() for p in paths]
    lm = {"AutoCVSS + DeepSeek-V4-Pro": sframes([LLM / "deepseek-v4-pro_DTD_s0" / "predictions.parquet"]),
          "AutoCVSS + Qwen3-8B": sframes([LLM / "Qwen3-8B_DTD_s0" / "predictions.parquet"]),
          "TF-IDF + LR": sframes([PRED / "T2_temporal_tfidf_lr.parquet"]),
          "DeBERTa + 辅助": sframes([ENC / f"T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s{s}" / "pred_latent.parquet" for s in range(5)])}
    snd = (sub["label_type"] != "derived").to_numpy()
    lines += ["\n## D. 大模型样本中有 NVD v3.1 的 CVE\n", f"共 {len(sub):,} 条（derived {int((~snd).sum()):,}，非 derived {int(snd.sum()):,}）。\n",
              "| 范围 | 方法 | 7 项吻合率（对 NVD） | 等级相同（对 NVD） | 比 NVD 低 / 高 | 等级准确率（对 CNA 标签） |", "|---|---|---|---|---|---|"]
    for sn, m in [("derived（VulDB）", ~snd), ("非 derived", snd)]:
        if m.sum() < 20:
            continue
        for name, fs in lm.items():
            ag = np.mean([match(shared_from_v4(f, ""), sref).mean(1) for f in fs], axis=0)
            bands = [Encoded(f).band for f in fs]
            lines.append(f"| {sn}（{int(m.sum()):,}） | {name} | {ag[m].mean():.3f} | {np.mean([(b == sref_band)[m].mean() for b in bands]):.3f} | "
                         f"{np.mean([(b < sref_band)[m].mean() for b in bands]):.3f} / {np.mean([(b > sref_band)[m].mean() for b in bands]):.3f} | {np.mean([(b == s_cna)[m].mean() for b in bands]):.3f} |")
        lines.append(f"| {sn}（{int(m.sum()):,}） | CNA 的 v4.0 标签本身 | {match(shared_from_v4(sub, 'y_'), sref)[m].mean():.3f} | {(s_cna[m] == sref_band[m]).mean():.3f} | "
                     f"{(s_cna[m] < sref_band[m]).mean():.3f} / {(s_cna[m] > sref_band[m]).mean():.3f} | — |")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
