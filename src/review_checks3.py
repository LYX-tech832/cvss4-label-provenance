"""第三份模拟审稿意见（9-30）的核查（CPU，几分钟）。

① VulnCheck 在 independent 测试集和非 derived 测试集中的准确占比。
② 逐指标"虚高"改用准确率（不受"真值和预测都没出现的类记 0 分"影响）：全部 vs 非 derived。
③ 敏感性：把 VulnCheck 也当作派生来源（它在测试期内越来越接近规则 R）时，虚高和大模型排名翻转是否还在。
④ 取值分布：VulDB 与 independent 来源在 AT、UI、SC/SI/SA 上的取值比例；v3.1 为 UI:R 时 v4 记为 P 还是 A。
输出：results/review_checks/summary3.md
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aggregate_seeds import Encoded, fast_scores  # noqa: E402
from baselines_v0 import CUTOFF, M40, evaluate, load, source_type_map  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
PRED = ROOT / "results" / "baselines_v0" / "predictions"
LLM = ROOT / "results" / "autocvss_baseline" / "deepseek-v4-pro_DTD_s0"


def aligned(path, ids):
    return pd.read_parquet(path).set_index("cve_id").loc[ids].reset_index()


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    lines = ["# 第三份审稿意见的核查（自动生成）\n"]

    # ①
    ind = test["label_type"] == "independent"
    nd = test["label_type"] != "derived"
    vc = test["source"] == "VulnCheck"
    lines += ["## ① VulnCheck 的占比（时间划分测试集）\n",
              f"- independent 测试集 {int(ind.sum()):,} 条，其中 VulnCheck {int((ind & vc).sum()):,} 条（{(ind & vc).sum() / ind.sum():.1%}）；",
              f"- 非 derived 测试集 {int(nd.sum()):,} 条，其中 VulnCheck {int((nd & vc).sum()):,} 条（{(nd & vc).sum() / nd.sum():.1%}）。"]

    # ②
    tf = aligned(PRED / "T2_temporal_tfidf_lr.parquet", test["cve_id"])
    aux = [aligned(d / "pred_latent.parquet", test["cve_id"]) for d in sorted(ENC.glob("T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s[0-9]"))]
    lines += ["\n## ② 逐指标准确率：全部 / 非 derived / derived（TF-IDF；DeBERTa+辅助为 5 种子均值）\n",
              "| 指标 | TF-IDF 全部 | 非 derived | derived | 差（全部 − 非 derived） | DeBERTa+辅助 全部 | 非 derived | derived | 差 |", "|---|---|---|---|---|---|---|---|---|"]
    der = (test["label_type"] == "derived").to_numpy()
    for k in M40:
        t = test["y_" + k].to_numpy()
        a_tf = tf[k].to_numpy() == t
        a_ax = np.mean([p[k].to_numpy() == t for p in aux], axis=0)
        lines.append(f"| {k} | {a_tf.mean():.3f} | {a_tf[~der].mean():.3f} | {a_tf[der].mean():.3f} | {a_tf.mean() - a_tf[~der].mean():+.3f} | "
                     f"{a_ax.mean():.3f} | {a_ax[~der].mean():.3f} | {a_ax[der].mean():.3f} | {a_ax.mean() - a_ax[~der].mean():+.3f} |")

    # ③
    lines += ["\n## ③ 把 VulnCheck 也当作派生来源\n", "| 方法 | 口径 | n | 平均宏 F1 | 等级准确率 |", "|---|---|---|---|---|"]
    scopes = [("全部", np.ones(len(test), bool)), ("非 derived（论文口径）", nd.to_numpy()),
              ("非 derived 且不含 VulnCheck", (nd & ~vc).to_numpy())]
    for name, m in scopes:
        r = evaluate(test[m].reset_index(drop=True), tf[m].reset_index(drop=True))
        lines.append(f"| TF-IDF | {name} | {int(m.sum()):,} | {r['mean_macro_f1']:.3f} | {r['band_acc']:.3f} |")
        rs = [evaluate(test[m].reset_index(drop=True), p[m].reset_index(drop=True)) for p in aux]
        lines.append(f"| DeBERTa+辅助 | {name} | {int(m.sum()):,} | {np.mean([x['mean_macro_f1'] for x in rs]):.3f} | {np.mean([x['band_acc'] for x in rs]):.3f} |")
    # 大模型对比：样本中去掉 VulnCheck
    llm = pd.read_parquet(LLM / "predictions.parquet")
    ids = llm["cve_id"]
    s = df.set_index("cve_id").loc[ids].reset_index()
    t_enc = Encoded(s, "y_")
    e_llm = Encoded(llm.set_index("cve_id").loc[ids].reset_index())
    e_tf = Encoded(aligned(PRED / "T2_temporal_tfidf_lr.parquet", ids))
    lt = s["label_type"].to_numpy()
    svc = (s["source"] == "VulnCheck").to_numpy()
    rng = np.random.default_rng(0)
    lines += ["\n大模型样本（2,000 条，类型内配对 bootstrap 1,000 次）：DeepSeek − TF-IDF 的平均宏 F1 差\n",
              "| 口径 | n | 其中 VulnCheck | 差值 [95%] |", "|---|---|---|---|"]
    for name, types, drop_vc in [("非 derived（论文口径）", ["independent", "v4_only", "other"], False),
                                 ("非 derived 且不含 VulnCheck", ["independent", "v4_only", "other"], True),
                                 ("independent 且不含 VulnCheck", ["independent"], True),
                                 ("independent 中的 VulnCheck", ["independent"], None)]:
        strata = []
        for ty in types:
            m = lt == ty
            if drop_vc is True:
                m &= ~svc
            elif drop_vc is None:
                m &= svc
            strata.append(np.flatnonzero(m))
        idx = np.concatenate(strata)
        point = fast_scores(t_enc, e_llm, idx)["mean_macro_f1"] - fast_scores(t_enc, e_tf, idx)["mean_macro_f1"]
        boots = []
        for _ in range(1000):
            b = np.concatenate([rng.choice(x, size=len(x), replace=True) for x in strata if len(x)])
            boots.append(fast_scores(t_enc, e_llm, b)["mean_macro_f1"] - fast_scores(t_enc, e_tf, b)["mean_macro_f1"])
        lines.append(f"| {name} | {len(idx):,} | {int(svc[idx].sum()):,} | {point:+.3f} [{np.percentile(boots, 2.5):+.3f}, {np.percentile(boots, 97.5):+.3f}] |")

    # ④
    lines += ["\n## ④ 取值分布（全部数据）\n", "| 来源 | n | AT:N | SC:N | SI:N | SA:N | UI:N | UI:P | UI:A | v3.1 为 UI:R 时 v4 记为 P / A |", "|---|---|---|---|---|---|---|---|---|---|"]
    groups = [("VulDB", df["source"] == "VulDB"), ("independent 全部", df["label_type"] == "independent"),
              ("independent 不含 VulnCheck", (df["label_type"] == "independent") & (df["source"] != "VulnCheck")),
              ("VulnCheck", df["source"] == "VulnCheck"), ("v4-only", df["label_type"] == "v4_only"), ("other", df["label_type"] == "other")]
    for name, m in groups:
        g = df[m]
        ur = g[g["x31_UI"] == "R"]
        pa = f"{(ur['y_UI'] == 'P').mean():.1%} / {(ur['y_UI'] == 'A').mean():.1%}（n={len(ur):,}）" if len(ur) else "—"
        lines.append(f"| {name} | {len(g):,} | {(g['y_AT'] == 'N').mean():.1%} | {(g['y_SC'] == 'N').mean():.1%} | {(g['y_SI'] == 'N').mean():.1%} | "
                     f"{(g['y_SA'] == 'N').mean():.1%} | {(g['y_UI'] == 'N').mean():.1%} | {(g['y_UI'] == 'P').mean():.1%} | {(g['y_UI'] == 'A').mean():.1%} | {pa} |")
    out = ROOT / "results" / "review_checks" / "summary3.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
