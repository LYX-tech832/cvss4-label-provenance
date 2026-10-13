"""三项补充分析（10-08；CPU，约 5 分钟；只读已有的预测和数据）。

A. NVD 参照里"评估者不同"与"版本不同"的分离：在同时有 CNA v3.1、CNA v4.0 和 NVD v3.1 向量的 CVE 上，
   逐项比较 ①同一 CNA 的 v3.1 向量 对 NVD 的 v3.1 向量（同版本，只有评估者不同）与
   ②同一 CNA 的 v4.0 向量 对 NVD 的 v3.1 向量（论文表 S34 的口径，评估者和版本都不同）。
   7 项的定义与 nvd_reference.py 相同：AV、AC、PR；UI 是否需要交互；C/I/A 对 max(V, S)。
B. 风险敏感解码按代价比选 α：每条低估计 r、高估计 1，α 在**验证集**上按期望代价最低来选，再报告测试集代价
   （表 S20 原来是在测试集上选的，只能算探索性比较）。DeBERTa + 辅助任务读各种子的 risk_decode.json（逐种子选 α，
   测试代价取 5 个种子的平均）；TF-IDF 和流水线读 risk_baselines_temporal.json（选 α 用的验证概率来自只在训练部分前 90% 上拟合的模型）。
C. 论文主结果表要补的行：DeBERTa 流水线、规则 R 伪标签、顺序微调（种子 0–2），SecureBERT 的两个模型（种子 0–4），
   时间划分，全部 / 非 derived；并重算已有的 DeBERTa 两行作核对。
输出：results/review_checks/summary17.md
"""

import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded  # noqa: E402
from baselines_v0 import M31, load, source_type_map  # noqa: E402
from nvd_reference import SHARED, match, nvd_vectors, shared_from_v4  # noqa: E402
from review_checks9 import band31  # noqa: E402
from review_gpu4_summary import COLS, describe  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
OUT = ROOT / "results" / "review_checks" / "summary17.md"


def part_a(df, lines):
    nvd = nvd_vectors()
    d = df[df["cve_id"].isin(nvd) & df["has_v31"]].reset_index(drop=True)
    ref = {k: np.array([nvd[c][0][k] for c in d["cve_id"]]) for k in M31}
    ref_band = np.array([nvd[c][1] for c in d["cve_id"]])
    own31 = {k: d["x31_" + k].to_numpy() for k in M31}
    m31 = match(own31, ref)                       # CNA v3.1 对 NVD v3.1：7 项
    m40 = match(shared_from_v4(d, "y_"), ref)     # CNA v4.0 对 NVD v3.1：7 项
    s_eq = (own31["S"] == ref["S"]).astype(float)
    b31, b40 = band31(d, "x31_"), Encoded(d, "y_").band
    main = ["VulDB", "VulnCheck", "GitHub_M"]
    groups = [("VulDB（derived）", (d["source"] == "VulDB").to_numpy()), ("VulnCheck", (d["source"] == "VulnCheck").to_numpy()),
              ("GitHub", (d["source"] == "GitHub_M").to_numpy()), ("其他来源", (~d["source"].isin(main)).to_numpy()),
              ("非 derived 合计", (d["label_type"] != "derived").to_numpy())]
    lines += ["## A. 同一批 CVE 上，CNA 的 v3.1 向量和 v4.0 向量分别对 NVD 的 v3.1 向量\n",
              f"范围：同时有 CNA v3.1、CNA v4.0 和 NVD v3.1 向量的 CVE，共 {len(d):,} 条。每格：与 NVD 取值相同的比例。"
              "“7 项全同”不含 Scope；“向量全同”是 v3.1 的 8 个指标全部相同（与 Note S9 的 3.1% / 14.2% / 28.4% 同一口径）。\n",
              "| 来源 | n | 比较 | " + " | ".join(SHARED) + " | 7 项全同 | Scope | 向量全同 | 等级相同 | CNA 更低 / 更高 |",
              "|---|---|---|" + "---|" * (len(SHARED) + 5)]
    for name, m in groups:
        if m.sum() < 30:
            lines.append(f"| {name} | {int(m.sum())} | 不足 30 条，不列 |" + " |" * (len(SHARED) + 5))
            continue
        full = (m31[m].all(1) & (s_eq[m] == 1)).mean()
        lines.append(f"| {name} | {int(m.sum()):,} | CNA v3.1 对 NVD v3.1 | " + " | ".join(f"{m31[m][:, j].mean():.3f}" for j in range(len(SHARED)))
                     + f" | {m31[m].all(1).mean():.3f} | {s_eq[m].mean():.3f} | {full:.3f} | {(b31[m] == ref_band[m]).mean():.3f} | "
                     f"{(b31[m] < ref_band[m]).mean():.3f} / {(b31[m] > ref_band[m]).mean():.3f} |")
        lines.append(f"| | | CNA v4.0 对 NVD v3.1 | " + " | ".join(f"{m40[m][:, j].mean():.3f}" for j in range(len(SHARED)))
                     + f" | {m40[m].all(1).mean():.3f} | — | — | {(b40[m] == ref_band[m]).mean():.3f} | "
                     f"{(b40[m] < ref_band[m]).mean():.3f} / {(b40[m] > ref_band[m]).mean():.3f} |")
        lines.append(f"| | | 差（v4.0 − v3.1） | " + " | ".join(f"{m40[m][:, j].mean() - m31[m][:, j].mean():+.3f}" for j in range(len(SHARED)))
                     + f" | {m40[m].all(1).mean() - m31[m].all(1).mean():+.3f} | — | — | {(b40[m] == ref_band[m]).mean() - (b31[m] == ref_band[m]).mean():+.3f} | — |")
    # 同一 CNA 自己的两个版本在 7 项上是否相同（版本之间改了多少）
    self_eq = match(shared_from_v4(d, "y_"), own31)
    lines += ["\n同一 CNA 的 v4.0 向量与它自己的 v3.1 向量在 7 项上相同的比例（版本之间改了多少）：\n",
              "| 来源 | n | " + " | ".join(SHARED) + " | 7 项全同 |", "|---|---|" + "---|" * (len(SHARED) + 1)]
    for name, m in groups:
        if m.sum() >= 30:
            lines.append(f"| {name} | {int(m.sum()):,} | " + " | ".join(f"{self_eq[m][:, j].mean():.3f}" for j in range(len(SHARED))) + f" | {self_eq[m].all(1).mean():.3f} |")


def part_b(lines):
    ratios = (1, 2, 5, 10)

    def cost(row, part, r):
        u = row[f"{part}_under_rate"]
        return r * u + (1 - row[f"{part}_band_acc"] - u)
    lines += ["\n## B. 按代价比在验证集上选 α（每条低估计 r、高估计 1；时间划分）\n",
              "每格：验证集选出的 α / 该 α 的测试集代价 / argmax 的测试集代价 /（测试集上代价最低的 α 及其代价，仅作对照）。"
              "DeBERTa + 辅助任务逐种子选 α，代价取 5 个种子的平均，α 列出 5 个种子各自选中的值。\n",
              "| 方法 | r = 1 | r = 2 | r = 5 | r = 10 |", "|---|---|---|---|---|"]
    runs = [json.loads((ENC / f"T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s{s}" / "risk_decode.json").read_text(encoding="utf-8")) for s in range(5)]
    cells = []
    for r in ratios:
        picks, tests, argm = [], [], []
        for run in runs:
            best = min(run["scan"], key=lambda row: cost(row, "val", r))
            picks.append(best["alpha"])
            tests.append(cost(best, "test", r))
            argm.append(cost(next(row for row in run["scan"] if abs(row["alpha"] - 1.0) < 1e-9), "test", r))
        alphas = sorted({row["alpha"] for row in runs[0]["scan"]}, reverse=True)
        mean_test = {a: np.mean([cost(next(row for row in run["scan"] if abs(row["alpha"] - a) < 1e-9), "test", r) for run in runs]) for a in alphas}
        oracle = min(mean_test, key=mean_test.get)
        cells.append(f"α = {', '.join(f'{a:.1f}' for a in picks)} / {np.mean(tests):.3f} / {np.mean(argm):.3f} /（{oracle:.1f}：{mean_test[oracle]:.3f}）")
    lines.append("| DeBERTa + v3.1 辅助 | " + " | ".join(cells) + " |")
    rb = json.loads((ROOT / "results" / "review_checks" / "risk_baselines_temporal.json").read_text(encoding="utf-8"))
    for name, key in [("TF-IDF + LR", "tfidf"), ("TF-IDF 流水线（规则 R）", "pipeline_R")]:
        scan = rb[key]["scan"]
        cells = []
        for r in ratios:
            best = min(scan, key=lambda row: cost(row, "val", r))
            arg = next(row for row in scan if abs(row["alpha"] - 1.0) < 1e-9)
            oracle = min(scan, key=lambda row: cost(row, "test", r))
            cells.append(f"α = {best['alpha']:.1f} / {cost(best, 'test', r):.3f} / {cost(arg, 'test', r):.3f} /（{oracle['alpha']:.1f}：{cost(oracle, 'test', r):.3f}）")
        lines.append(f"| {name} | " + " | ".join(cells) + " |")
    lines.append("\n（TF-IDF 和流水线的验证集取值来自只在训练部分前 90% 上拟合的模型，测试集取值来自在全部训练部分上拟合的模型；见 risk_decode_baselines.py。）")


def part_c(df, lines):
    rows = [("DeBERTa（选中的 25 轮，种子 0–4；核对）", [ENC / f"T2_temporal_deberta-v3-base_none_e25_cwinv_sqrt_s{s}" for s in range(5)]),
            ("DeBERTa + v3.1 aux.（种子 0–4；核对）", [ENC / f"T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s{s}" for s in range(5)]),
            ("规则 R 伪标签（种子 0–2）", [ENC / f"T2_temporal_deberta-v3-base_none_pseudo_e5_cwinv_sqrt_s{s}" for s in range(3)]),
            ("顺序微调，25 轮（种子 0–2）", [ENC / f"T2_temporal_deberta-v3-base_none_e25_cwinv_sqrt_seq_s{s}" for s in range(3)]),
            ("DeBERTa 流水线（种子 0–2）", [ENC / f"T2_temporal_deberta-v3-base_none_v31only_e5_s{s}" for s in range(3)]),
            ("SecureBERT（种子 0–4）", [ENC / f"T2_temporal_SecureBERT_none_e5_cwinv_sqrt_s{s}" for s in range(5)]),
            ("SecureBERT + v3.1 aux.（种子 0–4）", [ENC / f"T2_temporal_SecureBERT_none_aux_lam1_e5_cwinv_sqrt_s{s}" for s in range(5)])]
    lines += ["\n## C. 主结果表要补的行（时间划分；各种子平均）\n"]
    for scope, title in [("all", "全部（21,900）"), ("non_derived", "非 derived（16,749）")]:
        lines += [f"\n### {title}\n", "| 方法 | " + " | ".join(n for _, n in COLS) + " | 种子数 |", "|---|" + "---|" * (len(COLS) + 1)]
        for name, dirs in rows:
            dd = {i: d for i, d in enumerate(dirs) if (d / "pred_latent.parquet").exists()}
            m = describe(dd, df, scope)
            lines.append(f"| {name} | " + " | ".join(f"{m[k][0]:.3f}" for k, _ in COLS) + f" | {len(dd)} |")


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    lines = ["# NVD 参照中评估者与版本的分离、按期望代价选 α、主结果表的补充行（自动生成）\n"]
    part_a(df, lines)
    part_b(lines)
    part_c(df, lines)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\n已写入 {OUT}")


if __name__ == "__main__":
    main()
