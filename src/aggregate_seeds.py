"""多种子汇总与配对比较（CPU）：比较"有 / 无 v3.1 辅助任务"。

从 results/encoder/ 读取所有 T2 运行（运行名见 train_encoder.py），按（划分, 配置, 种子）配对：
  配置 = 除"是否辅助"以外的超参数（轮数、类别加权）；辅助版本的 λ 单独作为配置的一部分记录。
指标从 pred_latent.parquet 重新计算，口径分两种：全部测试集、去掉 derived 标签（VulDB 等）。
统计（论文第 5.5 节的口径）：
  - 每个（划分, 版本）的均值 ± 标准差；
  - **主检验：各划分内的配对 bootstrap**——对该划分的测试 CVE 有放回重抽样 1,000 次，每次对两个版本各自的所有种子
    求指标再按种子平均，取差值（有辅助 − 无辅助），报告 95% 百分位区间。不跨划分合并检验（各划分测试集不同）；
    5 个种子也不做秩检验（n=5 时 Wilcoxon 双侧最小 p 值为 0.0625）；
  - 描述性汇总：全部（划分, 种子）配对中，差值 > 0 的有几对。
输出：results/encoder/aggregate_seeds.md
用法：python src/aggregate_seeds.py [--config_none e5_cwinv_sqrt] [--config_aux e5] [--lam 1]
（有/无辅助两个版本可以各自使用在验证集上选出的最佳配置）
"""

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import M40, SEVERITY_ORDER, evaluate, load, source_type_map, to_vector, v4_score  # noqa: E402
from cvss_utils import V40_METRICS  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
NAME = re.compile(r"^T2_(?P<split>.+?)_deberta-v3-base_none(?P<aux>_aux)?(?:_lam(?P<lam>[0-9.]+))?(?P<cfg>(?:_e\d+)?(?:_cw\w+?)?)_s(?P<seed>\d+)$")
KEYS = ["mean_macro_f1", "exact_match", "score_mae", "band_acc", "under_rate", "hc_recall"]


def metrics(run_dir, df):
    p = pd.read_parquet(run_dir / "pred_latent.parquet")
    t = df.set_index("cve_id").loc[p["cve_id"]].reset_index()
    out = {}
    for scope, m in [("all", np.ones(len(t), bool)), ("non_derived", (t["label_type"] != "derived").values)]:
        if m.sum() >= 30:
            r = evaluate(t[m].reset_index(drop=True), p[m].reset_index(drop=True))
            out[scope] = {k: r[k] for k in KEYS}
    return out


class Encoded:
    """把一组预测（或真实标签）编码成便于快速重抽样计算的数组：各指标的整数编码、CVSS-B 分数、严重性等级序号。"""

    def __init__(self, frame, prefix=""):
        self.codes = {k: frame[prefix + k].map({v: i for i, v in enumerate(V40_METRICS[k])}).to_numpy() for k in M40}
        vecs = frame[[prefix + k for k in M40]].set_axis(M40, axis=1).apply(to_vector, axis=1)
        sc = [v4_score(v) for v in vecs]
        self.score = np.array([s for s, _ in sc], dtype=float)
        self.band = np.array([SEVERITY_ORDER.get(b, -1) for _, b in sc])


def fast_scores(t, p, idx):
    """与 evaluate() 同一口径（宏 F1 用完整标签集，未出现的类记 0 分），但只算重抽样需要的几项，速度快得多。"""
    f1s = []
    for k in M40:
        n_cls = len(V40_METRICS[k])
        cm = np.bincount(t.codes[k][idx] * n_cls + p.codes[k][idx], minlength=n_cls * n_cls).reshape(n_cls, n_cls)
        tp = np.diag(cm)
        denom = 2 * tp + (cm.sum(0) - tp) + (cm.sum(1) - tp)
        f1s.append(np.where(denom > 0, 2 * tp / np.maximum(denom, 1), 0.0).mean())
    tb, pb = t.band[idx], p.band[idx]
    return {"mean_macro_f1": float(np.mean(f1s)), "band_acc": float((tb == pb).mean()), "under_rate": float((pb < tb).mean()),
            "score_mae": float(np.nanmean(np.abs(t.score[idx] - p.score[idx])))}


BOOT_KEYS = ["mean_macro_f1", "band_acc", "under_rate", "score_mae"]


def paired_bootstrap(df, dirs_none, dirs_aux, B=1000, seed=0):
    """一个划分内：两个版本（各若干种子）在同一批测试 CVE 上的差值（有辅助 − 无辅助）及其 95% 百分位区间。"""
    ids = pd.read_parquet(next(iter(dirs_none.values())) / "pred_latent.parquet")["cve_id"]
    truth = df.set_index("cve_id").loc[ids].reset_index()
    t = Encoded(truth, "y_")
    enc = {v: [Encoded(pd.read_parquet(d / "pred_latent.parquet").set_index("cve_id").loc[ids].reset_index())
               for d in dirs.values()] for v, dirs in [("none", dirs_none), ("aux", dirs_aux)]}
    rng = np.random.default_rng(seed)
    out = {}
    for scope, mask in [("all", np.ones(len(truth), bool)), ("non_derived", (truth["label_type"] != "derived").to_numpy())]:
        pool = np.flatnonzero(mask)
        if len(pool) < 30:
            continue

        def diff(idx):
            per_run = {v: [fast_scores(t, p, idx) for p in enc[v]] for v in enc}
            avg = {v: {k: np.mean([r[k] for r in rs]) for k in BOOT_KEYS} for v, rs in per_run.items()}
            return {k: avg["aux"][k] - avg["none"][k] for k in BOOT_KEYS}

        point = diff(pool)
        boots = [diff(rng.choice(pool, size=len(pool), replace=True)) for _ in range(B)]
        out[scope] = {k: (point[k], *np.percentile([b[k] for b in boots], [2.5, 97.5])) for k in BOOT_KEYS} | {"n": len(pool)}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config_none", default="", help="无辅助版本的配置后缀，例如 e5_cwinv_sqrt；空字符串 = 默认配置")
    ap.add_argument("--config_aux", default="", help="有辅助版本的配置后缀（不含 λ）")
    ap.add_argument("--lam", default="0.5", help="辅助版本使用的 λ，如 0.5 或 1")
    ap.add_argument("--boot", type=int, default=1000, help="配对 bootstrap 的重抽样次数（0 = 不做）")
    args = ap.parse_args()
    cfg = {"none": ("_" + args.config_none) if args.config_none else "", "aux": ("_" + args.config_aux) if args.config_aux else ""}
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")

    runs = defaultdict(dict)  # (split, version) -> {seed: metrics}
    dirs = defaultdict(dict)  # (split, version) -> {seed: 运行目录}
    for d in sorted(ENC.iterdir()):
        m = NAME.match(d.name)
        if not m or not (d / "pred_latent.parquet").exists():
            continue
        ver = "aux" if m["aux"] else "none"
        if m["cfg"] != cfg[ver] or (ver == "aux" and float(m["lam"] or 0.5) != float(args.lam)):
            continue
        runs[(m["split"], ver)][int(m["seed"])] = metrics(d, df)
        dirs[(m["split"], ver)][int(m["seed"])] = d

    lines = [f"# 多种子汇总（无辅助配置 '{args.config_none or '默认'}'；有辅助配置 '{args.config_aux or '默认'}'，λ = {args.lam}）\n"]
    for scope in ["all", "non_derived"]:
        lines += [f"\n## 口径：{'全部测试集' if scope == 'all' else '去掉 derived 标签'}\n",
                  "| 划分 | 版本 | 种子数 | " + " | ".join(KEYS) + " |", "|---" * (3 + len(KEYS)) + "|"]
        for (split, ver), seeds in sorted(runs.items()):
            vals = {k: [s[scope][k] for s in seeds.values() if scope in s] for k in KEYS}
            if not vals["mean_macro_f1"]:
                continue  # 该口径下没有样本（例如留一 VulDB 时测试集全是 derived）
            lines.append(f"| {split} | {ver} | {len(vals['mean_macro_f1'])} | " + " | ".join(f"{np.mean(v):.3f}±{np.std(v, ddof=1) if len(v) > 1 else 0:.3f}" for v in vals.values()) + " |")
        # 配对差值与 Wilcoxon 检验
        diffs = defaultdict(list)
        per_split = defaultdict(lambda: defaultdict(list))
        for (split, ver), seeds in runs.items():
            if ver != "aux" or (split, "none") not in runs:
                continue
            for seed, a in seeds.items():
                b = runs[(split, "none")].get(seed)
                if b and scope in a and scope in b:
                    for k in KEYS:
                        diffs[k].append(a[scope][k] - b[scope][k])
                        per_split[split][k].append(a[scope][k] - b[scope][k])
        n = len(diffs["mean_macro_f1"])
        lines += [f"\n描述性汇总：全部（划分, 种子）配对的差值（有辅助 − 无辅助），共 {n} 对（不作显著性检验，见第 5.5 节）：",
                  "| 指标 | 平均差值 | 差值 > 0 的对数 |", "|---|---|---|"]
        for k in KEYS:
            d = np.array(diffs[k])
            lines.append(f"| {k} | {d.mean():+.4f} | {(d > 0).sum()}/{n} |" if n else f"| {k} | - | - |")
        if not n:
            continue
        lines.append("\n各划分的平均差值（平均F1 / 等级准确率 / 低估率）：" + "；".join(
            f"{s}: {np.mean(v['mean_macro_f1']):+.3f} / {np.mean(v['band_acc']):+.3f} / {np.mean(v['under_rate']):+.3f}（{len(v['mean_macro_f1'])} 对）"
            for s, v in sorted(per_split.items())))

    # 主检验：各划分内的配对 bootstrap（论文第 5.5 节）
    if args.boot > 0:
        lines += [f"\n## 各划分内的配对 bootstrap（有辅助 − 无辅助；先按种子平均；{args.boot} 次重抽样；95% 百分位区间）\n",
                  "| 划分 | 口径 | n | 种子数（无/有） | 平均宏 F1 差 | 等级准确率差 | 低估率差 | 分数 MAE 差 |", "|---|---|---|---|---|---|---|---|"]
        for split in sorted({s for s, _ in dirs}):
            if (split, "none") not in dirs or (split, "aux") not in dirs:
                continue
            res = paired_bootstrap(df, dirs[(split, "none")], dirs[(split, "aux")], B=args.boot)
            for scope, r in res.items():
                cells = " | ".join(f"{r[k][0]:+.3f} [{r[k][1]:+.3f}, {r[k][2]:+.3f}]" for k in BOOT_KEYS)
                lines.append(f"| {split} | {'全部' if scope == 'all' else '去掉 derived'} | {r['n']:,} | "
                             f"{len(dirs[(split, 'none')])}/{len(dirs[(split, 'aux')])} | {cells} |")
        lines.append("\n区间不含 0 即表示在该划分上差异稳定。低估率和 MAE 越小越好，所以这两列的差值为负才表示改进。")
    out = ENC / "aggregate_seeds.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
