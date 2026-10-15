"""Stability of the LLM baseline over repeated runs (CPU): the same CVEs queried several times with the same settings, to see how much
the results vary with sampling.

Reads the main run (2,000 CVEs) and the repeated runs of run_autocvss_baseline.py --run_tag repN (the same 200 CVEs) and, on the CVEs
covered by the repeated runs, reports:
  - the metrics of each run (overall and by label type) and the mean ± standard deviation across runs;
  - agreement of the raw answers: the share of (CVE, metric) with the same answer in every run (per metric); the share of CVEs with the
    same complete vector and the same severity band. Also the pairwise agreement (agreement between every two runs, averaged), used to
    compare settings with different numbers of runs (e.g. three runs at the default temperature, two at temperature 0).
Output: results/autocvss_baseline/repeat_variance_<main run directory>.md
Usage: python src/llm_repeat_variance.py [--main_dir results/autocvss_baseline/deepseek-v4-pro_DTD_s0]
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
        sys.exit("no repeated runs found (output directories of --run_tag repN)")
    runs = {"main": main_dir, **{d.name.rsplit("_", 1)[1]: d for d in reps}}
    cves = pd.read_parquet(reps[0] / "predictions.parquet")["cve_id"]

    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    test = df.set_index("cve_id").loc[cves].reset_index()
    preds = {n: pd.read_parquet(d / "predictions.parquet").set_index("cve_id").loc[cves].reset_index() for n, d in runs.items()}
    raws = {n: raw_labels(d) for n, d in runs.items()}

    info = json.loads((reps[0] / "results.json").read_text(encoding="utf-8"))
    temp = info.get("temperature")
    lines = [f"# Stability of the LLM baseline over repeated runs (the same {len(cves)} CVEs, {len(runs)} runs, generated automatically)\n",
             f"- Identical settings in every run: {info['model']}, AutoCVSS {info['prompt']} prompt, thinking mode {info.get('thinking')}, "
             f"sampling temperature {'API default (not set by AutoCVSS)' if temp is None else temp}",
             "- The standard deviation reflects only the randomness of the LLM's sampling, not the sampling error of drawing other CVEs\n",
             "## Metrics: each run and mean ± standard deviation\n",
             "| Scope | Run | " + " | ".join(c for _, c in COLS) + " |", "|---|---|" + "---|" * len(COLS)]
    for scope in ["overall"] + TYPES:
        m = np.ones(len(test), bool) if scope == "overall" else (test["label_type"] == scope).values
        res = {n: evaluate(test[m].reset_index(drop=True), p[m].reset_index(drop=True)) for n, p in preds.items()}
        for n, r in res.items():
            lines.append(f"| {scope} (n={m.sum()}) | {n} | " + " | ".join(f"{r[k]:.3f}" for k, _ in COLS) + " |")
        lines.append(f"| {scope} (n={m.sum()}) | **mean ± sd** | " + " | ".join(
            f"{np.mean([r[k] for r in res.values()]):.3f} ± {np.std([r[k] for r in res.values()], ddof=1):.3f}" for k, _ in COLS) + " |")

    lines += ["\n## Agreement of the raw answers\n", "Share of (CVE, metric) with the same answer in all runs (DONT_KNOW counts as an answer):\n",
              "| Metric | " + " | ".join(M40) + " | Mean |", "|---|" + "---|" * (len(M40) + 1)]
    pairs = list(combinations(runs, 2))
    agree = {k: np.mean([len({raws[n].get((c, k)) for n in runs}) == 1 for c in cves]) for k in M40}
    pair_agree = {k: np.mean([np.mean([raws[a].get((c, k)) == raws[b].get((c, k)) for c in cves]) for a, b in pairs]) for k in M40}
    lines.append(f"| Same in all {len(runs)} runs | " + " | ".join(f"{agree[k]:.3f}" for k in M40) + f" | {np.mean(list(agree.values())):.3f} |")
    lines.append("| Pairwise agreement (mean) | " + " | ".join(f"{pair_agree[k]:.3f}" for k in M40) + f" | {np.mean(list(pair_agree.values())):.3f} |")
    dk = {n: round(float(np.mean([raws[n].get((c, k)) in (None, "DONT_KNOW") for c in cves for k in M40])), 3) for n in runs}
    vec = {n: p[M40].apply(to_vector, axis=1) for n, p in preds.items()}
    same_vec = np.mean([len({vec[n].iloc[i] for n in runs}) == 1 for i in range(len(cves))])
    pair_vec = np.mean([np.mean(vec[a].values == vec[b].values) for a, b in pairs])
    band = {n: [v4_score(v)[1] for v in vec[n]] for n in runs}
    same_band = np.mean([len({band[n][i] for n in runs}) == 1 for i in range(len(cves))])
    pair_band = np.mean([np.mean([x == y for x, y in zip(band[a], band[b])]) for a, b in pairs])
    lines += ["", f"- Share of CVEs with the same complete vector: same in all {len(runs)} runs {same_vec:.3f}; pairwise mean {pair_vec:.3f}",
              f"- Share of CVEs with the same severity band: same in all {len(runs)} runs {same_band:.3f}; pairwise mean {pair_band:.3f}",
              f"- Share of DONT_KNOW answers (or failed requests) in each run: {dk}"]
    out = main_dir.parent / f"repeat_variance_{main_dir.name}.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nwritten to {out}")


if __name__ == "__main__":
    main()
