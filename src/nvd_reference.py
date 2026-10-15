"""The NVD's own v3.1 assessments as a second, independent assessor (CPU, about 3 minutes).

Data: probe/nvd_v4_records.jsonl (NVD records with a v4.0 vector, retrieved through the NVD CVE API 2.0 on 2026-09-25; the v3.1 vectors
with source nvd@nist.gov were assessed independently by NVD analysts). The NVD gives almost no v4.0 vectors (only 5), so the comparison
is limited to the content both versions share:
  AV, AC, PR compared directly; UI compared as "user interaction required or not" (v4.0's P and A both count as required);
  C/I/A compared with v4.0's max(VC, SC), max(VI, SI), max(VA, SA) (v3.1 impacts do not separate the vulnerable and subsequent systems);
  severity band: the NVD's v3.1 band against the CVSS-B band of the v4.0 vector (the two versions score differently; for reference only).
A. Coverage. B. Agreement of each source's CNA labels with the NVD. C. Results of each method against the NVD on the temporal split test
set. D. DeepSeek and the supervised models against the NVD on the LLM sample (for the question whether the LLM's higher ratings of
VulDB's vulnerabilities are more appropriate).
Output: results/review_checks/summary13.md
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
    """v4.0 vector (label or prediction) -> the 7 items comparable with v3.1."""
    g = lambda k: frame[prefix + k].to_numpy()  # noqa: E731
    mx = lambda a, b: np.where(np.vectorize(LEVEL.get)(a) >= np.vectorize(LEVEL.get)(b), a, b)  # noqa: E731
    return {"AV": g("AV"), "AC": g("AC"), "PR": g("PR"), "UI": np.where(g("UI") == "N", "N", "R"),
            "C": mx(g("VC"), g("SC")), "I": mx(g("VI"), g("SI")), "A": mx(g("VA"), g("SA"))}


def match(v4, ref):
    """Agreement of each CVE on the 7 items (0/1 matrix, columns in the order of SHARED)."""
    return np.column_stack([(v4[k] == ref[k]).astype(float) for k in SHARED])


def main():
    df = load()
    df["label_type"] = df["source"].map(source_type_map()).fillna("other")
    nvd = nvd_vectors()
    df = df[df["cve_id"].isin(nvd)].reset_index(drop=True)
    ref = {k: np.array([nvd[c][0][k] for c in df["cve_id"]]) for k in ["AV", "AC", "PR", "UI", "C", "I", "A", "S"]}
    ref_band = np.array([nvd[c][1] for c in df["cve_id"]])
    full = load()
    lines = ["# The NVD's v3.1 assessments as a second, independent assessor (generated automatically)\n",
             "Only the content both versions share is compared: AV, AC, PR; whether user interaction is required; C/I/A against max(V, S); the band is the NVD's v3.1 band against the CVSS-B band of the v4.0 vector.\n",
             "## A. Coverage\n",
             f"CVEs with a CNA v4.0 label: {len(full):,}, of which {len(df):,} have an NVD-assigned v3.1 vector ({len(df) / len(full):.1%}). "
             f"Of the temporal split test set (published in 2026, {int((full['pub'] >= CUTOFF).sum()):,} CVEs), {int((df['pub'] >= CUTOFF).sum()):,} have one "
             f"({(df['pub'] >= CUTOFF).sum() / (full['pub'] >= CUTOFF).sum():.1%}).\n",
             "| Source | v4.0 labels | With NVD v3.1 | Share | Of which in 2026 |", "|---|---|---|---|---|"]
    groups = [("VulDB (derived)", "VulDB"), ("VulnCheck", "VulnCheck"), ("GitHub", "GitHub_M")]
    masks = [(n, (df["source"] == s).to_numpy(), (full["source"] == s).to_numpy()) for n, s in groups]
    masks.append(("other sources", (~df["source"].isin([s for _, s in groups])).to_numpy(), (~full["source"].isin([s for _, s in groups])).to_numpy()))
    is_test = (df["pub"] >= CUTOFF).to_numpy()
    for n, m, mf in masks:
        lines.append(f"| {n} | {int(mf.sum()):,} | {int(m.sum()):,} | {m.sum() / mf.sum():.1%} | {int((m & is_test).sum()):,} |")

    # B. CNA 标签对 NVD
    truth = shared_from_v4(df, "y_")
    mt = match(truth, ref)
    t_band = Encoded(df, "y_").band
    lines += ["\n## B. Agreement of each source's CNA v4.0 labels with the NVD (all CVEs with an NVD v3.1 vector)\n",
              "| Source | n | " + " | ".join(SHARED) + " | All 7 items equal | Same band | CNA lower / higher |", "|---|---|" + "---|" * (len(SHARED) + 3)]
    for n, m, _ in masks + [("all", np.ones(len(df), bool), None), ("non-derived total", (df["label_type"] != "derived").to_numpy(), None)]:
        lines.append(f"| {n} | {int(m.sum()):,} | " + " | ".join(f"{mt[m][:, j].mean():.3f}" for j in range(len(SHARED)))
                     + f" | {mt[m].all(1).mean():.3f} | {(t_band[m] == ref_band[m]).mean():.3f} | {(t_band[m] < ref_band[m]).mean():.3f} / {(t_band[m] > ref_band[m]).mean():.3f} |")
    lines.append("\nThe NVD's v3.1 band distribution against the CNA's v4.0 band distribution (Low / Medium / High / Critical):")
    for n, m, _ in masks:
        d1 = np.bincount(ref_band[m], minlength=5)[1:] / m.sum()
        d2 = np.bincount(t_band[m], minlength=5)[1:] / m.sum()
        lines.append(f"- {n}: NVD " + " / ".join(f"{x:.2f}" for x in d1) + "; CNA " + " / ".join(f"{x:.2f}" for x in d2))
    dual = df["has_v31"].to_numpy()
    lines += ["\nShare of the same CNA's v3.1 vectors that are identical to the NVD's v3.1 vectors (dual-scored CVEs): " + "; ".join(
        f"{n} {np.mean([all(r['x31_' + k] == nvd[r['cve_id']][0][k] for k in M31) for _, r in df[m & dual].iterrows()]):.1%} (n = {int((m & dual).sum()):,})"
        for n, m, _ in masks if (m & dual).sum() >= 30) + "."]

    # C. 各方法对 NVD（时间划分测试集）
    test = df[is_test].reset_index(drop=True)
    ids = test["cve_id"]
    tref = {k: v[is_test] for k, v in ref.items()}
    tband = ref_band[is_test]
    cna_band = t_band[is_test]

    def frames(paths):
        return [pd.read_parquet(p).set_index("cve_id").loc[ids].reset_index() for p in paths]
    methods = {"TF-IDF + LR": frames([PRED / "T2_temporal_tfidf_lr.parquet"]),
               "pipeline (rule R, no v4.0 labels)": frames([PIPE / "T2_temporal_pipeline_rule_R.parquet"]),
               "DeBERTa (25 epochs)": frames([ENC / f"T2_temporal_deberta-v3-base_none_e25_cwinv_sqrt_s{s}" / "pred_latent.parquet" for s in range(5)]),
               "DeBERTa + auxiliary": frames([ENC / f"T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s{s}" / "pred_latent.parquet" for s in range(5)])}
    per = {}
    for name, fs in methods.items():
        agree = np.mean([match(shared_from_v4(f, ""), tref).mean(1) for f in fs], axis=0)       # 每条 CVE 的 7 项平均吻合
        bands = [Encoded(f).band for f in fs]
        per[name] = {"agree": agree, "band_nvd": np.mean([(b == tband) for b in bands], axis=0), "under_nvd": np.mean([(b < tband) for b in bands], axis=0),
                     "band_cna": np.mean([(b == cna_band) for b in bands], axis=0)}
    nd = (test["label_type"] != "derived").to_numpy()
    lines += ["\n## C. Results of each method against the NVD on the temporal split test set\n",
              f"Test CVEs with an NVD v3.1 vector: {len(test):,} (derived {int((~nd).sum()):,}, non-derived {int(nd.sum()):,}). "
              "Agreement on the 7 items = mean agreement of the predicted v4.0 vector with the NVD on the 7 shared items; the last column is the band accuracy against the CNA labels on the same CVEs, for comparison.\n",
              "| Scope | Method | Agreement on the 7 items (vs NVD) | Same band (vs NVD) | Lower than NVD | Band accuracy (vs CNA labels) |", "|---|---|---|---|---|---|"]
    scopes = [("all", np.ones(len(test), bool)), ("derived (VulDB)", ~nd), ("non-derived", nd)]
    for sn, m in scopes:
        for name in methods:
            p = per[name]
            lines.append(f"| {sn} ({int(m.sum()):,}) | {name} | {p['agree'][m].mean():.3f} | {p['band_nvd'][m].mean():.3f} | {p['under_nvd'][m].mean():.3f} | {p['band_cna'][m].mean():.3f} |")
        lines.append(f"| {sn} ({int(m.sum()):,}) | the CNA's v4.0 labels themselves | {mt[is_test][m].mean():.3f} | {(cna_band[m] == tband[m]).mean():.3f} | {(cna_band[m] < tband[m]).mean():.3f} | — |")
    lines += ["\nPaired differences (test CVEs resampled 1,000 times, 95% interval):\n", "| A − B | Scope | Agreement on the 7 items (vs NVD) | Same band (vs NVD) | Band accuracy (vs CNA labels) |", "|---|---|---|---|---|"]
    for a, b in [("TF-IDF + LR", "pipeline (rule R, no v4.0 labels)"), ("DeBERTa + auxiliary", "pipeline (rule R, no v4.0 labels)"), ("DeBERTa + auxiliary", "DeBERTa (25 epochs)")]:
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
          "DeBERTa + auxiliary": sframes([ENC / f"T2_temporal_deberta-v3-base_none_aux_e5_cwinv_sqrt_s{s}" / "pred_latent.parquet" for s in range(5)])}
    snd = (sub["label_type"] != "derived").to_numpy()
    lines += ["\n## D. CVEs of the LLM sample with an NVD v3.1 vector\n", f"{len(sub):,} CVEs (derived {int((~snd).sum()):,}, non-derived {int(snd.sum()):,}).\n",
              "| Scope | Method | Agreement on the 7 items (vs NVD) | Same band (vs NVD) | Lower / higher than NVD | Band accuracy (vs CNA labels) |", "|---|---|---|---|---|---|"]
    for sn, m in [("derived (VulDB)", ~snd), ("non-derived", snd)]:
        if m.sum() < 20:
            continue
        for name, fs in lm.items():
            ag = np.mean([match(shared_from_v4(f, ""), sref).mean(1) for f in fs], axis=0)
            bands = [Encoded(f).band for f in fs]
            lines.append(f"| {sn} ({int(m.sum()):,}) | {name} | {ag[m].mean():.3f} | {np.mean([(b == sref_band)[m].mean() for b in bands]):.3f} | "
                         f"{np.mean([(b < sref_band)[m].mean() for b in bands]):.3f} / {np.mean([(b > sref_band)[m].mean() for b in bands]):.3f} | {np.mean([(b == s_cna)[m].mean() for b in bands]):.3f} |")
        lines.append(f"| {sn} ({int(m.sum()):,}) | the CNA's v4.0 labels themselves | {match(shared_from_v4(sub, 'y_'), sref)[m].mean():.3f} | {(s_cna[m] == sref_band[m]).mean():.3f} | "
                     f"{(s_cna[m] < sref_band[m]).mean():.3f} / {(s_cna[m] > sref_band[m]).mean():.3f} | — |")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
