"""Second encoder: temporal split, with and without the v3.1 auxiliary task, 5 seeds each after configuration selection on the
validation set.

Subcommands (both read only existing runs under results/encoder/; no GPU needed):
  select   selects one configuration for each variant from the seed-0 candidates by the best mean validation macro-F1, as for DeBERTa:
           baseline: class weighting {none, inv_sqrt} × epoch cap {5, 10}, plus the step-matched 25 epochs (class-weighted);
           auxiliary: λ {0.5, 1} × class weighting {none, inv_sqrt}, 5 epochs.
           Writes results/encoder/selected_config_<model short name>.json; with --shell, prints only the two argument lines for the scripts.
  summary  per-seed results, means and standard deviations of the selected configurations, the gain of the auxiliary task (paired
           bootstrap and per-seed differences), and the comparison with DeBERTa. Writes results/review_gpu/summary6.md.
Usage: python src/second_encoder.py select|summary [--model ehsanaghaei/SecureBERT] [--shell]
Running select / summary with --model microsoft/deberta-v3-base checks the script: it should select 25 epochs (0.6769) and λ = 0.5 with
weighting (0.6948), gain +0.025 [+0.023, +0.026].
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
OUT = ROOT / "results" / "review_gpu" / "summary6.md"
NONE_GRID = {(5, "none"), (5, "inv_sqrt"), (10, "none"), (10, "inv_sqrt"), (25, "inv_sqrt")}
PLAIN = {"aux_shuffle": False, "aux_cwe": False, "pseudo_v4": False, "v31_only": False, "no_cwe_in_text": False, "train_frac": 1.0,
         "exclude_ids": None, "init_encoder": None, "save_encoder": False, "frac_mode": "random"}


def runs(model):
    """The model's plain runs on the temporal split: returns [(variant, configuration, seed, directory)]; configuration = (epoch cap, class weighting, λ)."""
    out = []
    for d in sorted(ENC.iterdir()):
        f = d / "args.json"
        if not f.exists() or not (d / "results.json").exists():
            continue
        a = json.loads(f.read_text(encoding="utf-8"))
        if a.get("model") != model or a.get("task") != "T2" or a.get("split") != "temporal" or a.get("source_mode") != "none" or a.get("smoke_test"):
            continue
        if any(a.get(k, v) != v for k, v in PLAIN.items()):
            continue
        if a.get("aux_v31"):
            if a["epochs"] == 5 and a.get("aux_lambda") in (0.5, 1.0) and a.get("aux_max", 60000) == 60000:
                out.append(("aux", (5, a.get("class_weight", "none"), a["aux_lambda"]), a["seed"], d))
        elif (a["epochs"], a.get("class_weight", "none")) in NONE_GRID:
            out.append(("none", (a["epochs"], a.get("class_weight", "none"), None), a["seed"], d))
    return out


def val(d):
    r = json.loads((d / "results.json").read_text(encoding="utf-8"))
    return r["val_best_mean_f1"], r["best_epoch"]


def select(model, quiet=False):
    cand = {"none": {}, "aux": {}}
    for ver, cfg, seed, d in runs(model):
        if seed == 0:
            cand[ver][cfg] = (*val(d), d.name)
    chosen = {}
    for ver in ("none", "aux"):
        if not cand[ver]:
            continue
        best = max(cand[ver], key=lambda c: cand[ver][c][0])
        args = f"--epochs {best[0]} --class_weight {best[1]}" + (f" --aux_v31 --aux_lambda {best[2]:g}" if ver == "aux" else "")
        chosen[ver] = {"config": list(best), "val_best_mean_f1": cand[ver][best][0], "run": cand[ver][best][2], "args": args,
                       "candidates": {f"e{c[0]}_{c[1]}" + (f"_lam{c[2]:g}" if c[2] else ""): round(v[0], 4) for c, v in sorted(cand[ver].items())}}
        if not quiet:
            print(f"[{ver}] candidates (best mean validation macro-F1):")
            for c, v in sorted(cand[ver].items(), key=lambda x: -x[1][0]):
                print(f"   {v[0]:.4f}  best epoch {v[1] + 1}  {v[2]}")
    return chosen


def summary(model):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from aggregate_seeds import Encoded, fast_scores, paired_bootstrap  # noqa: E402
    from baselines_v0 import CUTOFF, load, source_type_map  # noqa: E402

    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    test = df[df["pub"] >= CUTOFF].reset_index(drop=True)
    t = Encoded(test, "y_")
    scopes = {"all": np.arange(len(test)), "non-derived": np.flatnonzero((test["label_type"] != "derived").to_numpy())}
    keys = ["mean_macro_f1", "band_acc", "under_rate", "score_mae"]
    lines = ["# Second encoder: does the gain of the v3.1 auxiliary task depend on the encoder? (temporal split, generated automatically)\n"]
    gains, encs = {}, {}
    for m in [model, "microsoft/deberta-v3-base"]:
        ch = select(m, quiet=True)
        if set(ch) != {"none", "aux"}:
            lines.append(f"\n## {m}: candidate configurations not all finished, skipped\n")
            continue
        allruns = runs(m)
        dirs = {ver: {s: d for v, c, s, d in allruns if v == ver and list(c) == ch[ver]["config"]} for ver in ("none", "aux")}
        lines += [f"\n## {m}\n", "Configurations selected on the validation set (seed 0): baseline " + ch["none"]["args"] + f" ({ch['none']['val_best_mean_f1']:.4f}); auxiliary " + ch["aux"]["args"] + f" ({ch['aux']['val_best_mean_f1']:.4f}).",
                  "Validation scores of the candidates: baseline " + json.dumps(ch["none"]["candidates"]) + "; auxiliary " + json.dumps(ch["aux"]["candidates"]) + "\n",
                  "| Variant | Seeds | Scope | Mean macro-F1 (mean ± sd) | Band accuracy | Underestimation | MAE |", "|---|---|---|---|---|---|---|"]
        per = {}
        for ver in ("none", "aux"):
            es = encs[(m, ver)] = {s: Encoded(pd.read_parquet(d / "pred_latent.parquet").set_index("cve_id").loc[test["cve_id"]].reset_index()) for s, d in sorted(dirs[ver].items())}
            for sc, idx in scopes.items():
                rs = {s: fast_scores(t, e, idx) for s, e in es.items()}
                per[(ver, sc)] = rs
                f = [r["mean_macro_f1"] for r in rs.values()]
                lines.append(f"| {'baseline' if ver == 'none' else 'with v3.1 auxiliary'} | {sorted(rs)} | {sc} | {np.mean(f):.3f} ± {np.std(f, ddof=1) if len(f) > 1 else float('nan'):.3f} | "
                             + " | ".join(f"{np.mean([r[k] for r in rs.values()]):.3f}" for k in keys[1:]) + " |")
        common = sorted(set(dirs["none"]) & set(dirs["aux"]))
        if len(common) < 2:
            lines.append("\nFewer than 2 seeds common to both variants; no gain computed.")
            continue
        bs = paired_bootstrap(df, {s: dirs["none"][s] for s in common}, {s: dirs["aux"][s] for s in common})
        lines += [f"\nGain (auxiliary − baseline; seeds {common}; paired bootstrap, 1,000 resamples, 95% interval):\n", "| Scope | Mean macro-F1 | Band accuracy | Underestimation | Per-seed mean macro-F1 difference |", "|---|---|---|---|---|"]
        for sc, key in [("all", "all"), ("non-derived", "non_derived")]:
            b = bs[key]
            seedwise = ", ".join(f"{per[('aux', sc)][s]['mean_macro_f1'] - per[('none', sc)][s]['mean_macro_f1']:+.3f}" for s in common)
            lines.append(f"| {sc} | " + " | ".join(f"{b[k][0]:+.3f} [{b[k][1]:+.3f}, {b[k][2]:+.3f}]" for k in keys[:3]) + f" | {seedwise} |")
        gains[m] = bs["all"]["mean_macro_f1"][0]
    if len(gains) == 2:
        a, b = gains[model], gains["microsoft/deberta-v3-base"]
        lines.append(f"\n**Comparison**: gain in mean macro-F1, {Path(model).name} {a:+.3f}, DeBERTa-v3-base {b:+.3f}.")
    pf = ROOT / "results" / "pipeline_baseline" / "predictions" / "T2_temporal_pipeline_rule_R.parquet"
    if pf.exists():
        # 与表 S33 相同的比较：直接预测 v4.0 的模型 − 不用 v4.0 标签的 TF-IDF 流水线（规则 R）
        pe = Encoded(pd.read_parquet(pf).set_index("cve_id").loc[test["cve_id"]].reset_index())
        rng = np.random.default_rng(0)

        def sc(es, ix):
            rs = [fast_scores(t, e, ix) for e in es]
            return np.array([np.mean([r[k] for r in rs]) for k in keys[:3]])
        lines += ["\n## Comparison with the TF-IDF pipeline (rule R, no v4.0 labels): model − pipeline (averaged over seeds; paired bootstrap, 1,000 resamples, 95% interval)\n",
                  "The two DeBERTa rows are a check: the point estimates should equal Table S33 of the paper; the intervals may differ by 0.001 because of a different random-number sequence.\n",
                  "| Model | Scope | Mean macro-F1 | Band accuracy | Underestimation |", "|---|---|---|---|---|"]
        for (m, ver), es in encs.items():
            for sc_name, idx in scopes.items():
                d = sc(list(es.values()), idx) - sc([pe], idx)
                bs = np.array([sc(list(es.values()), ix) - sc([pe], ix) for ix in (rng.choice(idx, size=len(idx), replace=True) for _ in range(1000))])
                lines.append(f"| {Path(m).name} {'baseline' if ver == 'none' else 'with v3.1 auxiliary'} | {sc_name} | "
                             + " | ".join(f"{d[j]:+.3f} [{np.percentile(bs[:, j], 2.5):+.3f}, {np.percentile(bs[:, j], 97.5):+.3f}]" for j in range(3)) + " |")
        # DeBERTa 流水线（只学 v3.1 头，再用规则 R 转换；种子 0–2，论文 6.2 节）：不用 v4.0 标签的模型里等级准确率最高的一个
        dp = [ENC / f"T2_temporal_deberta-v3-base_none_v31only_e5_s{s}" / "pred_latent.parquet" for s in range(3)]
        if all(f.exists() for f in dp):
            dpe = [Encoded(pd.read_parquet(f).set_index("cve_id").loc[test["cve_id"]].reset_index()) for f in dp]
            lines += ["\n## Comparison with the DeBERTa pipeline (no v4.0 labels, averaged over seeds 0–2): model with v3.1 auxiliary − DeBERTa pipeline\n",
                      "Point estimates of the pipeline (for checking, Section 7.2: mean macro-F1 0.601, underestimation rate 0.111, non-derived band accuracy 0.561): "
                      + "; ".join(f"{n} mean macro-F1 {sc(dpe, ix)[0]:.3f}, band accuracy {sc(dpe, ix)[1]:.3f}, underestimation rate {sc(dpe, ix)[2]:.3f}" for n, ix in scopes.items()) + ".\n",
                      "| Model | Scope | Mean macro-F1 | Band accuracy | Underestimation |", "|---|---|---|---|---|"]
            for (m, ver), es in encs.items():
                if ver != "aux":
                    continue
                for sc_name, idx in scopes.items():
                    d = sc(list(es.values()), idx) - sc(dpe, idx)
                    bs = np.array([sc(list(es.values()), ix) - sc(dpe, ix) for ix in (rng.choice(idx, size=len(idx), replace=True) for _ in range(1000))])
                    lines.append(f"| {Path(m).name} with v3.1 auxiliary | {sc_name} | "
                                 + " | ".join(f"{d[j]:+.3f} [{np.percentile(bs[:, j], 2.5):+.3f}, {np.percentile(bs[:, j], 97.5):+.3f}]" for j in range(3)) + " |")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nwritten to {OUT}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["select", "summary"])
    ap.add_argument("--model", default="ehsanaghaei/SecureBERT")
    ap.add_argument("--shell", action="store_true", help="select: print only the two lines NONE_ARGS / AUX_ARGS, for eval in the scripts")
    a = ap.parse_args()
    if a.cmd == "summary":
        return summary(a.model)
    ch = select(a.model, quiet=a.shell)
    if set(ch) != {"none", "aux"}:
        print(f"candidates not all finished: {sorted(ch)}", file=sys.stderr)
        sys.exit(1)
    (ENC / f"selected_config_{Path(a.model).name}.json").write_text(json.dumps(ch, indent=1, ensure_ascii=False), encoding="utf-8")
    if a.shell:
        print(f'NONE_ARGS="{ch["none"]["args"]}"\nAUX_ARGS="{ch["aux"]["args"]}"')
    else:
        print("\nselected:\n  baseline " + ch["none"]["args"] + "\n  auxiliary " + ch["aux"]["args"])


if __name__ == "__main__":
    main()
