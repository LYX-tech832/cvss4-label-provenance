"""Three further analyses (CPU, about 5 minutes; reads only existing predictions and data).

A. Separating "different assessor" from "different version" in the NVD reference: on the CVEs with a CNA v3.1, a CNA v4.0 and an NVD
   v3.1 vector, item by item, (1) the same CNA's v3.1 vector against the NVD's v3.1 vector (same version, only the assessor differs) and
   (2) the same CNA's v4.0 vector against the NVD's v3.1 vector (as in Table S34; both assessor and version differ).
   The 7 items are defined as in nvd_reference.py: AV, AC, PR; whether user interaction is required; C/I/A against max(V, S).
B. Risk-sensitive decoding with α selected by cost ratio: r per underestimate and 1 per overestimate; α is selected on the **validation
   set** by the lowest expected cost, and the test cost is reported. DeBERTa + auxiliary task reads risk_decode.json of each seed (α
   selected per seed, test cost averaged over 5 seeds); TF-IDF and the pipeline read risk_baselines_temporal.json (the validation
   probabilities used to select α come from models fitted only on the first 90% of the training part).
C. Additional rows of the main results table: DeBERTa pipeline, rule-R pseudo-labels, sequential fine-tuning (seeds 0-2), the two
   SecureBERT models (seeds 0-4), temporal split, all / non-derived; the two existing DeBERTa rows are recomputed as a check.
Output: results/review_checks/summary17.md
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
    groups = [("VulDB (derived)", (d["source"] == "VulDB").to_numpy()), ("VulnCheck", (d["source"] == "VulnCheck").to_numpy()),
              ("GitHub", (d["source"] == "GitHub_M").to_numpy()), ("other sources", (~d["source"].isin(main)).to_numpy()),
              ("non-derived total", (d["label_type"] != "derived").to_numpy())]
    lines += ["## A. The CNA's v3.1 vector and its v4.0 vector, each against the NVD's v3.1 vector, on the same CVEs\n",
              f"Scope: CVEs with a CNA v3.1, a CNA v4.0 and an NVD v3.1 vector, {len(d):,} in total. Each cell: share with the same value as the NVD. "
              "\"All 7 equal\" excludes Scope; \"vector equal\" means all 8 v3.1 metrics are equal (the same definition as the 3.1% / 14.2% / 28.4% in Note S9).\n",
              "| Source | n | Comparison | " + " | ".join(SHARED) + " | All 7 equal | Scope | Vector equal | Same band | CNA lower / higher |",
              "|---|---|---|" + "---|" * (len(SHARED) + 5)]
    for name, m in groups:
        if m.sum() < 30:
            lines.append(f"| {name} | {int(m.sum())} | fewer than 30, not listed |" + " |" * (len(SHARED) + 5))
            continue
        full = (m31[m].all(1) & (s_eq[m] == 1)).mean()
        lines.append(f"| {name} | {int(m.sum()):,} | CNA v3.1 vs NVD v3.1 | " + " | ".join(f"{m31[m][:, j].mean():.3f}" for j in range(len(SHARED)))
                     + f" | {m31[m].all(1).mean():.3f} | {s_eq[m].mean():.3f} | {full:.3f} | {(b31[m] == ref_band[m]).mean():.3f} | "
                     f"{(b31[m] < ref_band[m]).mean():.3f} / {(b31[m] > ref_band[m]).mean():.3f} |")
        lines.append(f"| | | CNA v4.0 vs NVD v3.1 | " + " | ".join(f"{m40[m][:, j].mean():.3f}" for j in range(len(SHARED)))
                     + f" | {m40[m].all(1).mean():.3f} | — | — | {(b40[m] == ref_band[m]).mean():.3f} | "
                     f"{(b40[m] < ref_band[m]).mean():.3f} / {(b40[m] > ref_band[m]).mean():.3f} |")
        lines.append(f"| | | difference (v4.0 − v3.1) | " + " | ".join(f"{m40[m][:, j].mean() - m31[m][:, j].mean():+.3f}" for j in range(len(SHARED)))
                     + f" | {m40[m].all(1).mean() - m31[m].all(1).mean():+.3f} | — | — | {(b40[m] == ref_band[m]).mean() - (b31[m] == ref_band[m]).mean():+.3f} | — |")
    # 同一 CNA 自己的两个版本在 7 项上是否相同（版本之间改了多少）
    self_eq = match(shared_from_v4(d, "y_"), own31)
    lines += ["\nShare of the same CNA's v4.0 vectors equal to its own v3.1 vectors on the 7 items (how much changes between versions):\n",
              "| Source | n | " + " | ".join(SHARED) + " | All 7 equal |", "|---|---|" + "---|" * (len(SHARED) + 1)]
    for name, m in groups:
        if m.sum() >= 30:
            lines.append(f"| {name} | {int(m.sum()):,} | " + " | ".join(f"{self_eq[m][:, j].mean():.3f}" for j in range(len(SHARED))) + f" | {self_eq[m].all(1).mean():.3f} |")


def part_b(lines):
    ratios = (1, 2, 5, 10)

    def cost(row, part, r):
        u = row[f"{part}_under_rate"]
        return r * u + (1 - row[f"{part}_band_acc"] - u)
    lines += ["\n## B. α selected on the validation set by cost ratio (r per underestimate, 1 per overestimate; temporal split)\n",
              "Each cell: α selected on the validation set / test cost at that α / test cost of argmax / (the α with the lowest test cost and its cost, for comparison only). "
              "DeBERTa + auxiliary task selects α per seed; the cost is averaged over the 5 seeds, and the α column lists the value selected for each of the 5 seeds.\n",
              "| Method | r = 1 | r = 2 | r = 5 | r = 10 |", "|---|---|---|---|---|"]
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
        cells.append(f"α = {', '.join(f'{a:.1f}' for a in picks)} / {np.mean(tests):.3f} / {np.mean(argm):.3f} / ({oracle:.1f}: {mean_test[oracle]:.3f})")
    lines.append("| DeBERTa + v3.1 auxiliary | " + " | ".join(cells) + " |")
    rb = json.loads((ROOT / "results" / "review_checks" / "risk_baselines_temporal.json").read_text(encoding="utf-8"))
    for name, key in [("TF-IDF + LR", "tfidf"), ("TF-IDF pipeline (rule R)", "pipeline_R")]:
        scan = rb[key]["scan"]
        cells = []
        for r in ratios:
            best = min(scan, key=lambda row: cost(row, "val", r))
            arg = next(row for row in scan if abs(row["alpha"] - 1.0) < 1e-9)
            oracle = min(scan, key=lambda row: cost(row, "test", r))
            cells.append(f"α = {best['alpha']:.1f} / {cost(best, 'test', r):.3f} / {cost(arg, 'test', r):.3f} / ({oracle['alpha']:.1f}: {cost(oracle, 'test', r):.3f})")
        lines.append(f"| {name} | " + " | ".join(cells) + " |")
    lines.append("\n(The validation values of TF-IDF and the pipeline come from models fitted only on the first 90% of the training part, the test values from models fitted on the whole training part; see risk_decode_baselines.py.)")


def part_c(df, lines):
    rows = [("DeBERTa (selected 25 epochs, seeds 0–4; check)", [ENC / f"T2_temporal_deberta-v3-base_none_e25_cwinv_sqrt_s{s}" for s in range(5)]),
            ("DeBERTa + v3.1 aux. (seeds 0–4; check)", [ENC / f"T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s{s}" for s in range(5)]),
            ("rule-R pseudo-labels (seeds 0–2)", [ENC / f"T2_temporal_deberta-v3-base_none_pseudo_e5_cwinv_sqrt_s{s}" for s in range(3)]),
            ("sequential fine-tuning, 25 epochs (seeds 0–2)", [ENC / f"T2_temporal_deberta-v3-base_none_e25_cwinv_sqrt_seq_s{s}" for s in range(3)]),
            ("DeBERTa pipeline (seeds 0–2)", [ENC / f"T2_temporal_deberta-v3-base_none_v31only_e5_s{s}" for s in range(3)]),
            ("SecureBERT (seeds 0–4)", [ENC / f"T2_temporal_SecureBERT_none_e5_cwinv_sqrt_s{s}" for s in range(5)]),
            ("SecureBERT + v3.1 aux. (seeds 0–4)", [ENC / f"T2_temporal_SecureBERT_none_aux_lam1_e5_cwinv_sqrt_s{s}" for s in range(5)])]
    lines += ["\n## C. Additional rows of the main results table (temporal split; mean over seeds)\n"]
    for scope, title in [("all", "all (21,900)"), ("non_derived", "non-derived (16,749)")]:
        lines += [f"\n### {title}\n", "| Method | " + " | ".join(n for _, n in COLS) + " | Seeds |", "|---|" + "---|" * (len(COLS) + 1)]
        for name, dirs in rows:
            dd = {i: d for i, d in enumerate(dirs) if (d / "pred_latent.parquet").exists()}
            m = describe(dd, df, scope)
            lines.append(f"| {name} | " + " | ".join(f"{m[k][0]:.3f}" for k, _ in COLS) + f" | {len(dd)} |")


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    lines = ["# Assessor and version in the NVD reference, α selected by expected cost, additional rows of the main results table (generated automatically)\n"]
    part_a(df, lines)
    part_b(lines)
    part_c(df, lines)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nwritten to {OUT}")


if __name__ == "__main__":
    main()
