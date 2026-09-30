# Not All CVSS v4.0 Labels Are Equal — code and data

This repository accompanies the paper *Not All CVSS v4.0 Labels Are Equal: Provenance-Aware Evaluation and Cross-Version Transfer for Automated Vulnerability Severity Assessment* by Yuxin Liu, Yuxuan Ye and Jikui Wang (Jilin Normal University). The paper has not been published yet; its reference will be added here once it is.

It contains the code, the processed dataset, the provenance typing of CVE Numbering Authorities (CNAs), the predictions of all trained models and the answers of both LLMs to every request, so that every number in the paper can be recomputed.

## Contents

| Path | What it is |
|---|---|
| `src/` | All analysis, training and evaluation code (Python). Comments are partly in Chinese. |
| `scripts/` | Shell scripts used to run the GPU experiments on a rented Linux server. Paths such as `/root/...` refer to that server and need to be adapted. |
| `data/processed/cve_records.parquet` | One row per published CVE record of the CVE List snapshot of 25 September 2026 (see `NOTICE.md`). |
| `data/cve_ids_v4.csv` | The 37,997 CVEs with a CNA-provided CVSS v4.0 vector: CNA, publication date, label type, dual-scored flag, membership in the 2,000-CVE LLM sample. |
| `data/cve_ids_v31_pool.csv` | The 110,524 CVEs published before 2026 with a v3.1 vector but no CNA-provided v4.0 vector (auxiliary pool). |
| `probe/nvd_v4_records.jsonl` | NVD records with v4.0 scores used for the reanalysis in Section 7.2 (see `NOTICE.md`). |
| `results/` | All results: summaries (`*.md`), predictions of every model run (`results/encoder/<run>/pred_latent.parquet`), probabilities, LLM answers (`results/autocvss_baseline/`). |
| `external/` | Place AutoCVSS here (not included, see below). |

## Setup

Analyses run on a CPU; we used Python 3.14 on Windows.

```bash
pip install -r requirements.txt
```

Training the encoders requires a GPU (we used one NVIDIA RTX 4090 with PyTorch 2.13 and Transformers 5.17; see `src/requirements-gpu.txt`).

## Rebuilding the dataset (optional)

`data/processed/cve_records.parquet` is included. To rebuild it, download the release `2026-09-25_all_CVEs_at_midnight.zip.zip` of the CVE List repository (<https://github.com/CVEProject/cvelistV5>; SHA-256 `35f620251bc2efadd11fca5316085be0e729043af8b61e96b65347007ef7b97e`) and run

```bash
python src/build_cvelist_dataset.py path/to/2026-09-25_all_CVEs_at_midnight.zip.zip
```

## Reproducing the numbers in the paper (CPU)

Each command rewrites a result file under `results/`. With the included predictions, all of them reproduce the published files byte for byte (we checked this on 29 September 2026). Tables and figures are numbered as in the submitted manuscript; tables S1–S9 and Note S1 are in its supplementary material.

| Command | Paper | Time |
|---|---|---|
| `python src/label_provenance.py` | Section 4, Table 2, Table S1 | seconds |
| `python src/pairing_provenance.py` | Section 7.2, Table S2 | seconds |
| `python src/sensitivity_analyses.py` | Sections 4.3, 7.1 and 8.2 | 1 min |
| `python src/main_table.py` | Table 5 | 5 min |
| `python src/aggregate_seeds.py --config_none e5_cwinv_sqrt --config_aux e5_cwinv_sqrt --lam 0.5` | Section 7.3 (paired bootstrap) | 6 min |
| `python src/cwe_control.py` | Section 7.3 (CWE control) | 6 min |
| `python src/label_efficiency.py` | Section 7.4, Figure 3, Table S3 | 10 min |
| `python src/summarize_risk_decode.py` | Section 7.5, Table 6 | seconds |
| `python src/llm_bootstrap.py` | Section 7.1, Table 4 and its intervals | 1 min |
| `python src/llm_repeat_variance.py` | Section 7.6 (stability) | seconds |
| `python src/baselines_v0.py` | Classical baselines (retrains TF-IDF + LR), Table S9 | 15 min |
| `python src/review_checks.py` | Robustness checks: fallback of the dependence test, clean subset, LLM post-processing, monotonicity of CVSS-B, sources of the v3.1 pool (Sections 4.2–7.1, Table S4) | 2 min |
| `python src/review_checks2.py` | Training randomness, test-set weighting, per-metric inflation, near-duplicates, timing of labels, synthetic conventions (Sections 4.2, 7.1, 7.3, 8.2; Tables S4–S6, Note S1) | 15 min |
| `python src/risk_decode_baselines.py` | Risk-sensitive decoding for the TF-IDF baseline and the pipeline (Section 7.5, Table S7) | 1.5 h |
| `python src/fig1_rule_agreement.py`, `python src/fig2_protocol.py` | Figures 1 and 2 | seconds |
| `python src/review_gpu_summary.py` (added on 30 September 2026) | Ten-epoch training, pseudo-labels and DeBERTa pipeline (Sections 7.3 and 7.4, Tables S10 and S11) | 20 min |

On Windows, `python -X utf8 ...` avoids console encoding errors.

## Training the encoders (GPU)

`src/train_encoder.py` trains DeBERTa-v3-base with or without the v3.1 auxiliary task (`--aux_v31`), the CWE control (`--aux_cwe --no_cwe_in_text`), the label-efficiency variants (`--train_frac`), rule-R pseudo-labels (`--pseudo_v4`) and the DeBERTa pipeline (`--v31_only`). The scripts in `scripts/` run the full experiment batches (`run_w4_all.sh`: configuration search and five seeds on four splits; `run_w5_label_eff.sh`: label efficiency; `run_cwe_control.sh`: CWE control; `run_review_gpu.sh`: ten-epoch training, pseudo-labels and pipeline). `src/risk_decode.py` adds risk-sensitive decoding to finished runs.

## LLM baselines

We run AutoCVSS (<https://github.com/nec-research/AutoCVSS>) unchanged. Its licence does not permit redistribution, so it is not included: clone it into `external/AutoCVSS`. Our driver `src/run_autocvss_baseline.py` calls it without modification. The API key is read from the environment variable `OPENAI_API_KEY` or from a file `.deepseek_key` in the repository root; never commit that file (it is listed in `.gitignore`).

```bash
python src/run_autocvss_baseline.py --base_url https://api.deepseek.com --model deepseek-v4-pro --mode json
```

Qwen3-8B was served locally with vLLM 0.30.0 (`scripts/setup_llm_env.sh`, `scripts/run_llm_local.sh`). The answers of both LLMs to every request are in `results/autocvss_baseline/*/raw.jsonl`; the prompts are those of AutoCVSS.

## Notes

- The code was developed with the assistance of an AI tool (Claude Code), as stated in the paper's declaration on generative AI.
- Our code is released under the MIT licence (`LICENSE`). The data are subject to the terms listed in `NOTICE.md`. AutoCVSS is subject to its own licence and is not part of this repository.

## Citation

Please cite the paper; its reference will be added here once it is published.
