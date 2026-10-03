"""第二轮审稿次要意见 7：表 S7 的 TF-IDF 重拟合与表 7 差 ≤0.004 的原因。分别按原顺序和按发布日期排序重拟合，与存档预测比较（CPU，约 15 分钟）。"""
import sys
from pathlib import Path
import numpy as np, pandas as pd
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from baselines_v0 import CUTOFF, M40, load, evaluate, pred_tfidf_lr
df = load()
train, test = df[df["pub"] < CUTOFF], df[df["pub"] >= CUTOFF].reset_index(drop=True)
a = pred_tfidf_lr(train, test, False).reset_index(drop=True)
b = pred_tfidf_lr(train.sort_values("pub"), test, False).reset_index(drop=True)
orig = pd.read_parquet(ROOT / 'results' / 'baselines_v0' / 'predictions' / 'T2_temporal_tfidf_lr.parquet').set_index("cve_id").loc[test["cve_id"]].reset_index()
for name, p in [("refit, original order", a), ("refit, sorted by date", b)]:
    agree = {k: float((p[k].values == orig[k].values).mean()) for k in M40}
    r = evaluate(test, p.assign(cve_id=test["cve_id"]))
    print(name, "mean_macro_f1 %.4f band %.4f" % (r["mean_macro_f1"], r["band_acc"]), "min per-metric agreement with stored %.4f" % min(agree.values()))
ro = evaluate(test, orig)
print("stored predictions mean_macro_f1 %.4f band %.4f" % (ro["mean_macro_f1"], ro["band_acc"]))
