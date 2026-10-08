"""第四轮审稿意见的 GPU 实验汇总（scripts/run_review_gpu5.sh；CPU，约 20 分钟）。缺结果的部分会注明并跳过，可以边跑边汇总。

1. D0/D1：留一来源划分上步数相当的无辅助基线作为候选配置后，各划分按自己的验证集重新选配置；
   选中配置下辅助 − 无辅助的差值（共同种子），以及辅助 − 步数相当基线的差值（即使它没被选中）。
2. A：顺序微调基线（时间划分）：第二阶段三个轮数上限在验证集上的分数与选中的配置；与辅助任务、无辅助 25 轮比较（种子 0–2）。
3. B：留一来源划分上的打乱标签对照：正确标签 − 打乱标签；打乱标签 − 选中的无辅助配置（种子 0–2）。
4. C：最早的 5% v4 标签：辅助 vs 无辅助（50 轮）；与随机 5% 的结果并列。
输出：results/review_gpu/summary5.md
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import CUTOFF, load, source_type_map  # noqa: E402
from review_gpu4_summary import ENC, compare, describe, run_dirs, tag_of  # noqa: E402
from select_loso_config import NONE_LOSO_EXTRA, select  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "review_gpu" / "summary5.md"
LOSO = ["loso:VulnCheck", "loso:GitHub_M", "loso:VulDB"]
SHOW = [("mean_macro_f1", "平均宏 F1"), ("band_acc", "等级准确率"), ("under_rate", "低估率"), ("hc_recall", "H+C 召回")]


def val_and_epoch(split, tag, seed=0):
    f = ENC / f"T2_{split.replace(':', '-')}_deberta-v3-base_none{tag}_s{seed}" / "results.json"
    if not f.exists():
        return None
    r = json.loads(f.read_text(encoding="utf-8"))
    return r["val_best_mean_f1"], r["best_epoch"] + 1


def table(lines, df, rows, scopes):
    """rows: [(名称, {种子: 目录})]；每个口径一行。"""
    lines += ["| 模型 | 种子 | 口径 | " + " | ".join(n for _, n in SHOW) + " |", "|---|---|---|" + "---|" * len(SHOW)]
    for name, dirs in rows:
        if not dirs:
            lines.append(f"| {name} | — | — | " + " | ".join("尚无结果" for _ in SHOW) + " |")
            continue
        for scope in scopes:
            m = describe(dirs, df, scope)
            lines.append(f"| {name} | {sorted(dirs)} | {scope} | " + " | ".join(f"{m[k][0]:.3f} ± {m[k][1]:.3f}" for k, _ in SHOW) + " |")


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    lines = ["# 第四轮审稿意见的 GPU 实验汇总（自动生成）\n"]

    # ---------- 1. 留一来源划分：步数相当的无辅助基线 ----------
    sel = select()
    lines += ["## 1. 留一来源划分：步数相当的无辅助基线（D0 / D1）\n",
              "| 划分 | 候选配置（验证集平均宏 F1，种子 0） | 选中的无辅助配置 | 步数相当候选的最佳轮次 |", "|---|---|---|---|"]
    for sp in LOSO:
        sc = sel[sp]["none"]["scores"]
        extra = next(iter(NONE_LOSO_EXTRA[sp]))
        ve = val_and_epoch(sp, extra)
        lines.append(f"| {sp} | " + "；".join(f"`{t}` {'—' if s is None else f'{s:.4f}'}" for t, s in sc.items())
                     + f" | `{sel[sp]['none']['best']}`{'' if sel[sp]['none']['complete'] else '（候选未跑全）'} | {ve[1] if ve else '—'} |")
    for sp in LOSO:
        extra = next(iter(NONE_LOSO_EXTRA[sp]))
        ta, tn = tag_of(sel[sp]["aux"]["args"]), tag_of(sel[sp]["none"]["args"])
        d_aux, d_sel, d_extra = run_dirs(sp, ta), run_dirs(sp, tn), run_dirs(sp, extra)
        lines.append(f"\n### {sp}\n")
        table(lines, df, [(f"辅助 `{ta}`", d_aux), (f"无辅助（选中）`{tn}`", d_sel), (f"无辅助（步数相当）`{extra}`", d_extra)], ["all"])
        if d_extra:
            compare(lines, df, f"{sp}：辅助 − 无辅助（步数相当）", d_aux, d_extra, ["all"])
        if tn != extra:
            compare(lines, df, f"{sp}：辅助 − 无辅助（选中）", d_aux, d_sel, ["all"])

    # ---------- 2. 顺序微调 ----------
    lines += ["\n## 2. 顺序微调基线（A；时间划分）\n", "第一阶段：只用 6 万条 v3.1 池样本训练 v3.1 头 5 轮（与 DeBERTa 流水线相同），取验证集上最佳轮次的编码器；"
              "第二阶段：从这个编码器出发，只用 v4 标签微调（类别加权）。\n", "| 第二阶段轮数上限 | 验证集平均宏 F1（种子 0） | 最佳轮次 |", "|---|---|---|"]
    vals = {e: val_and_epoch("temporal", f"_e{e}_cwinv_sqrt_seq") for e in (5, 10, 25)}
    for e, v in vals.items():
        lines.append(f"| {e} | {'—' if v is None else f'{v[0]:.4f}'} | {'—' if v is None else v[1]} |")
    if all(v is not None for v in vals.values()):
        best = max(vals, key=lambda e: vals[e][0])
        seq = run_dirs("temporal", f"_e{best}_cwinv_sqrt_seq", range(3))
        aux, none25 = run_dirs("temporal", "_aux_e5_cwinv_sqrt", range(3)), run_dirs("temporal", "_e25_cwinv_sqrt", range(3))
        pseudo = run_dirs("temporal", "_pseudo_e5_cwinv_sqrt", range(3))
        lines.append(f"\n按验证集选中：{best} 轮。\n")
        table(lines, df, [("无辅助 25 轮", none25), (f"顺序微调（第二阶段 {best} 轮）", seq), ("v3.1 辅助 5 轮", aux), ("规则 R 伪标签 5 轮", pseudo)], ["all", "non_derived"])
        compare(lines, df, "辅助 − 顺序微调", aux, seq, ["all", "non_derived"])
        compare(lines, df, "顺序微调 − 无辅助 25 轮", seq, none25, ["all", "non_derived"])
    else:
        lines.append("\n第二阶段三个配置尚未跑全。")

    # ---------- 3. 留一来源划分上的打乱标签对照 ----------
    lines.append("\n## 3. 留一来源划分上的打乱标签对照（B；种子 0–2）\n")
    for sp in LOSO:
        ta, tn = tag_of(sel[sp]["aux"]["args"]), tag_of(sel[sp]["none"]["args"])
        ts = ta.replace("_aux", "_auxshuf", 1)
        d_aux, d_shuf, d_none = run_dirs(sp, ta, range(3)), run_dirs(sp, ts, range(3)), run_dirs(sp, tn, range(3))
        lines.append(f"\n### {sp}\n")
        table(lines, df, [(f"无辅助（选中）`{tn}`", d_none), (f"打乱 v3.1 标签 `{ts}`", d_shuf), (f"正确 v3.1 标签 `{ta}`", d_aux)], ["all"])
        if d_shuf:
            compare(lines, df, f"{sp}：正确标签 − 打乱标签", d_aux, d_shuf, ["all"])
            compare(lines, df, f"{sp}：打乱标签 − 无辅助（选中）", d_shuf, d_none, ["all"])

    # ---------- 4. 最早的 5% 标签 ----------
    lines.append("\n## 4. 最早的 5% v4 训练标签（C；种子 0–2）\n")
    rows = [("随机 5%：无辅助 50 轮", run_dirs("temporal", "_e50_cwinv_sqrt_frac0.05", range(3))),
            ("随机 5%：v3.1 辅助 5 轮", run_dirs("temporal", "_aux_e5_cwinv_sqrt_frac0.05", range(3))),
            ("最早 5%：无辅助 50 轮", run_dirs("temporal", "_e50_cwinv_sqrt_fracearly0.05", range(3))),
            ("最早 5%：v3.1 辅助 5 轮", run_dirs("temporal", "_aux_e5_cwinv_sqrt_fracearly0.05", range(3))),
            ("全部标签：无辅助 25 轮", run_dirs("temporal", "_e25_cwinv_sqrt", range(3)))]
    table(lines, df, rows, ["all", "non_derived"])
    if rows[3][1] and rows[2][1]:
        compare(lines, df, "最早 5%：辅助 − 无辅助", rows[3][1], rows[2][1], ["all", "non_derived"])
        compare(lines, df, "最早 5% 加辅助 − 全部标签无辅助 25 轮", rows[3][1], rows[4][1], ["all", "non_derived"])
    # 最早 5% 的构成（与 train_encoder.py 的取法相同：训练部分按发布日期排序后取前 5%）
    tr = df[df["pub"] < CUTOFF].sort_values("pub")
    tr = tr.iloc[:-max(1, int(0.1 * len(tr)))]
    early = tr.sort_values("pub", kind="stable").head(int(round(len(tr) * 0.05)))
    top = lambda d: "、".join(f"{s} {n / len(d):.1%}" for s, n in d["source"].value_counts().head(4).items())  # noqa: E731
    lines.append(f"\n最早 5%：{len(early):,} 条，发布于 {early['pub'].min():%Y-%m-%d} 至 {early['pub'].max():%Y-%m-%d}；来源：{top(early)}；"
                 f"标签类型：" + "、".join(f"{k} {v / len(early):.1%}" for k, v in early["label_type"].value_counts().items()) + "。"
                 f"\n全部训练标签：{len(tr):,} 条，发布于 {tr['pub'].min():%Y-%m-%d} 至 {tr['pub'].max():%Y-%m-%d}；来源：{top(tr)}。")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
