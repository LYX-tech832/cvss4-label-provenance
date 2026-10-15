"""Summary of the W3 GPU runs (results/encoder/*/results.json), compared with the CPU baselines.
Output: results/encoder/summary_w3.md
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENC = ROOT / "results" / "encoder"
BASE = json.loads((ROOT / "results" / "baselines_v0" / "metrics.json").read_text(encoding="utf-8"))


def load_runs():
    runs = {}
    for d in sorted(ENC.iterdir()):
        f = d / "results.json"
        if f.exists():
            runs[d.name] = json.loads(f.read_text(encoding="utf-8"))
    return runs


def fmt(r, keys=("mean_macro_f1", "exact_match", "score_mae", "band_acc", "under_rate", "hc_recall")):
    return " | ".join(f"{r[k]:.3f}" for k in keys)


def main():
    runs = load_runs()
    lines = ["# W3 GPU runs (DeBERTa-v3-base, seed 0, single run)\n",
             "Columns: mean F1 | exact vector | score MAE | band accuracy | underestimation rate | High+Critical recall\n",
             "## A. All test labels\n", "| Setting | Method | Mean F1 | Exact | MAE | Band accuracy | Underestimation | HC recall |", "|---|---|---|---|---|---|---|---|"]
    base_map = {"T2_temporal": ("T2|temporal", "tfidf_lr"), "T2_loso-VulnCheck": ("T2|loso:VulnCheck", "tfidf_lr"),
                "T2_loso-GitHub_M": ("T2|loso:GitHub_M", "tfidf_lr"), "T2_loso-VulDB": ("T2|loso:VulDB", "tfidf_lr"),
                "T1_temporal": ("T1|temporal", "rule_R")}
    for prefix, (bkey, bm) in base_map.items():
        b = BASE[bkey][bm]
        lines.append(f"| {prefix} | CPU baseline {bm} | {fmt(b)} |")
        for name, r in runs.items():
            if name.startswith(prefix + "_"):
                tag = name[len(prefix) + 1:].replace("deberta-v3-base_", "").replace("_s0", "")
                lines.append(f"| {prefix} | DeBERTa {tag} | {fmt(r['latent'])} |")

    lines += ["\n## B. By label type (T2 temporal split; mean F1 / v4-specific F1 / band accuracy / underestimation rate)\n",
              "| Method | derived | independent | v4_only | other |", "|---|---|---|---|---|"]
    bt = BASE["T2|temporal"]["tfidf_lr"]["by_type"]
    cell = lambda v: f"{v['mean_macro_f1']:.3f} / {v['v4_specific_f1']:.3f} / {v['band_acc']:.3f} / {v['under_rate']:.3f}"  # noqa: E731
    lines.append("| CPU baseline TF-IDF+LR | " + " | ".join(cell(bt[t]) if t in bt else "-" for t in ["derived", "independent", "v4_only", "other"]) + " |")
    for name, r in runs.items():
        if name.startswith("T2_temporal_"):
            tag = name.replace("T2_temporal_deberta-v3-base_", "").replace("_s0", "")
            lines.append(f"| DeBERTa {tag} | " + " | ".join(cell(r["by_type"][t]) if t in r.get("by_type", {}) else "-"
                                                          for t in ["derived", "independent", "v4_only", "other"]) + " |")

    lines += ["\n## C. Gain of the v3.1 auxiliary task (with − without, single run)\n", "| Split | Δ mean F1 | Δ exact | Δ MAE | Δ band accuracy | Δ underestimation |", "|---|---|---|---|---|---|"]
    for split in ["temporal", "loso-VulnCheck", "loso-GitHub_M", "loso-VulDB"]:
        a, b = runs.get(f"T2_{split}_deberta-v3-base_none_aux_s0"), runs.get(f"T2_{split}_deberta-v3-base_none_s0")
        if a and b:
            a, b = a["latent"], b["latent"]
            lines.append(f"| {split} | {a['mean_macro_f1'] - b['mean_macro_f1']:+.3f} | {a['exact_match'] - b['exact_match']:+.3f} | "
                         f"{a['score_mae'] - b['score_mae']:+.3f} | {a['band_acc'] - b['band_acc']:+.3f} | {a['under_rate'] - b['under_rate']:+.3f} |")
    out = ENC / "summary_w3.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
