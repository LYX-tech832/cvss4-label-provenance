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
| `probe/nvd_v4_records.jsonl` | NVD records with v4.0 scores used for the reanalysis in Note S4 of the supplementary material (see `NOTICE.md`). |
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

Each command rewrites a result file under `results/`. With the included predictions, the commands reproduced the published files byte for byte when we checked on 29 September 2026; commands added later are marked with their date. Tables and figures are numbered as in the manuscript; Tables S1–S39 and Notes S1–S9 are in its supplementary material.

| Command | Paper | Time |
|---|---|---|
| `python src/label_provenance.py` | Section 4, Table 2, Table S1 | seconds |
| `python src/pairing_provenance.py` | Note S4 and Table S2 of the supplementary material | seconds |
| `python src/sensitivity_analyses.py` | Sections 4.3, 7.1 and 8.2 | 1 min |
| `python src/main_table.py` | Table 4 (deterministic methods) | 5 min |
| `python src/aggregate_seeds.py --config_none e5_cwinv_sqrt --config_aux e5_cwinv_sqrt --lam 0.5` | Paired bootstrap with the five-epoch baseline (last column of Table S23; Note S6) | 6 min |
| `python src/cwe_control.py` | CWE control (Note S6) | 6 min |
| `python src/label_efficiency.py` | Section 7.3, Figure 4, Table S3 | 10 min |
| `python src/summarize_risk_decode.py` | Section 7.4, Table 5 | seconds |
| `python src/llm_bootstrap.py` | Section 7.5, Table 6 and its intervals | 1 min |
| `python src/llm_repeat_variance.py` | Section 7.5 (stability) | seconds |
| `python src/baselines_v0.py` | Classical baselines (retrains TF-IDF + LR), Table S9 | 15 min |
| `python src/review_checks.py` | Robustness checks: fallback of the dependence test, clean subset, LLM post-processing, monotonicity of CVSS-B, sources of the v3.1 pool (Sections 4.2–7.1, Table S4) | 2 min |
| `python src/review_checks2.py` | Training randomness, test-set weighting, per-metric inflation, near-duplicates, timing of labels, synthetic conventions (Sections 4.2, 7.1, 7.2, 8.2; Tables S4–S6, Note S1) | 15 min |
| `python src/risk_decode_baselines.py` | Risk-sensitive decoding for the TF-IDF baseline and the pipeline (Section 7.4, Table S7) | 1.5 h |
| `python src/fig1_rule_agreement.py`, `python src/fig2_protocol.py` | Figures 1 and 2 | seconds |
| `python src/review_checks3.py` (added on 30 September 2026) | VulnCheck share, per-metric accuracy, VulnCheck treated as derived, value distributions (Sections 4.3, 5.3, 7.1, 8.2; Table S12) | 3 min |
| `python src/review_checks5.py` (added on 1 October 2026) | Label-substitution control: the same predictions scored against original and rule-R-converted labels (Section 7.1; Table S15) | 5 min |
| `python src/review_checks6.py` (added on 1 October 2026) | Calibration of the functional-dependence test, source characteristics, vendor-cluster bootstrap, macro-F1 over present values, decision-oriented metrics of risk-sensitive decoding (Sections 4.3, 7.1, 7.4, 8.2; Tables S16–S22) | about 30 min |
| `python src/review_checks4.py` (added on 1 October 2026) | Transfer gains on labels that differ from rule R, bias of AT towards None, 5% labels on these subsets (Sections 7.2 and 7.3; Table S14) | 15 min |
| `python src/review_gpu_summary.py` (added on 30 September 2026) | Ten-epoch training, pseudo-labels and DeBERTa pipeline (Sections 7.2 and 7.3, Tables S10 and S11) | 20 min |
| `python src/review_checks7.py` (added on 2 October 2026) | Records with several vectors of one version; per-seed differences for the ten-epoch LOSO comparison (Section 4.1, Note S3, Table S23) | 5 min |
| `python src/review_baseline25.py` (added on 3 October 2026) | Tables that compare with the model without the auxiliary task, recomputed with the selected 25-epoch model (Table 4; Tables S5, S11, S15, S18, S21, S22; needs `data/raw/cves.zip` for the vendor clusters) | 15 min |
| `python src/llm_reversal_runs.py` (added on 3 October 2026) | Ranking reversal with the LLM's sampling randomness: three complete DeepSeek-V4-Pro runs, two-level bootstrap (Section 7.5; Table S29); reads the stored answers, no API calls | 2 min |
| `python src/review_checks8.py` (added on 3 October 2026) | Base-rate-corrected band accuracy and Cohen's κ per label type, TF-IDF baseline trained without VulDB's labels, rolling quarterly cut-offs (Section 7.1; Tables S26–S28) | 25 min |
| `python src/review_checks9.py` (added on 3 October 2026) | Predictability of the v3.1 and v4.0 labels of the same CVEs by source, CVE-identifier years of the test CVEs, source-macro averages, results without back-filled test CVEs (Sections 7.1, 7.2 and 8.2; Tables S30 and S31) | 15 min |
| `python src/audit_checks.py` (added on 3 October 2026) | Further controls: each source trained on 1,000 of its own labels, models trained on v4.0 labels against the TF-IDF pipeline on all and on non-derived labels, VulnCheck's rule agreement for recent and older vulnerabilities, all pairwise comparisons on the LLM sample (Sections 4.3, 7.1 and 7.2; Table S33) | 25 min |
| `python src/nvd_reference.py` (added on 4 October 2026) | The NVD's own v3.1 assessments as a second, independent assessor: agreement of each source's v4.0 labels and of each method's predictions with the NVD on the content that both versions share (reads `probe/nvd_v4_records.jsonl`; Sections 5.3, 7.1, 7.2 and 7.5; Tables S34 and S35, Note S9) | 3 min |
| `python src/fig4_ranking.py` (added on 4 October 2026) | Figure 3: band accuracy of four methods against the CNA labels (all and non-derived) and against the NVD's rating | 1 min |
| `python src/first_examples.py` (added on 3 October 2026) | Rule R applied to the example assessments published by FIRST (`data/external/first_v4_examples.csv`; Section 4.3, Note S5, Table S32) | seconds |
| `python src/review_tfidf_order.py` (added on 2 October 2026) | Cause of the small difference between the refitted TF-IDF models of Table S7 and Table 4 | 15 min |
| `python src/late_update_ids.py` (added on 2 October 2026) | CVEs whose CNA or ADP container was updated after the temporal cut-off (needs `data/raw/cves.zip`; input to `train_encoder.py --exclude_ids`) | 5 min |
| `python src/select_loso_config.py` (added on 2 October 2026) | Configuration selected on each split's own validation set (Table S25) | seconds |
| `python src/review_gpu4_summary.py` (added on 3 October 2026) | Main comparison with the selected configurations, step-matched baseline, timing sensitivity (Sections 7.2 and 8.2; Tables 4 and S23) | 25 min |
| `python src/review_gpu5_summary.py` (added on 5 October 2026) | Step-matched baselines on the LOSO splits, sequential fine-tuning, shuffled-label control on the LOSO splits, earliest 5% of the v4.0 labels (Sections 7.2 and 7.3; Tables S3, S10, S11, S23–S25 and S36) | 20 min |
| `python src/llm_decision_metrics.py` (added on 5 October 2026) | Underestimation rate and High+Critical recall of all methods on the 2,000-CVE sample of the LLM comparison, and the example of a v3.1 vector with its v4.0 vectors at VulDB and VulnCheck (Sections 4.3 and 7.5; Table S37) | 2 min |
| `python src/source_macro_ranking.py` (added on 5 October 2026) | Ranking of the methods, including the conversion pipelines, with equal weight per CNA (Sections 7.1 and 8.2; Table S31) | 3 min |
| `python src/review_checks10.py all` (added on 7 October 2026) | Sensitivity of the comparison between the TF-IDF baseline, the pipeline and the LLM to the regularisation strength and feature settings of the TF-IDF models, and the three-seed row of Table S14 (Sections 6.1, 7.1, 7.5 and 8.2; Tables S14 and S38). Predictions are cached in `results/tfidf_sensitivity/` | 30 min |
| `python src/second_encoder.py summary` (added on 8 October 2026) | Second encoder (SecureBERT) on the temporal split: selected configurations, results per version, gain of the auxiliary task with paired bootstrap intervals, and comparisons with DeBERTa-v3-base and with the two pipelines (Sections 6.2, 7.1, 7.2 and 8.2; Table S39). `second_encoder.py select` picks the configurations from the seed-0 candidates | 15 min |
| `python src/review_gpu4_tables.py` (added on 3 October 2026) | Rows of Tables 4, 5 and S24 for the selected configurations | 5 min |
| `python src/review_gpu2_summary.py` (added on 2 October 2026) | Shuffled-v3.1-label controls with all and with 5% of the v4.0 training labels, ten-epoch baselines on the LOSO splits (Sections 7.2 and 7.3; Tables S3, S10, S14 and S23) | 30 min |

On Windows, `python -X utf8 ...` avoids console encoding errors.

## Training the encoders (GPU)

`src/train_encoder.py` trains an encoder (DeBERTa-v3-base by default; `--model` selects another one) with or without the v3.1 auxiliary task (`--aux_v31`), the CWE control (`--aux_cwe --no_cwe_in_text`), the label-efficiency variants (`--train_frac`), rule-R pseudo-labels (`--pseudo_v4`), the DeBERTa pipeline (`--v31_only`), the shuffled-label control (`--aux_v31 --aux_shuffle`), the exclusion of CVEs updated after the cut-off (`--exclude_ids`), sequential fine-tuning (`--v31_only --save_encoder`, then `--init_encoder`) and the earliest instead of a random fraction of the labels (`--frac_mode earliest`). The scripts in `scripts/` run the full experiment batches (`run_w4_all.sh`: configuration search and five seeds on four splits; `run_w5_label_eff.sh`: label efficiency; `run_cwe_control.sh`: CWE control; `run_review_gpu.sh`: ten-epoch training, pseudo-labels and pipeline; `run_review_gpu2.sh` and `run_review_gpu3.sh`: shuffled-label controls and ten-epoch LOSO baselines; `run_review_gpu4.sh`: configuration selection on each split's validation set, step-matched baseline and timing sensitivity; `run_review_gpu5.sh`: step-matched baselines on the LOSO splits, sequential fine-tuning, shuffled-label control on the LOSO splits and the earliest 5% of the labels; `run_second_encoder.sh`: the baseline encoder and the auxiliary-task model with a second encoder, `--model ehsanaghaei/SecureBERT`, on the temporal split). `src/risk_decode.py` adds risk-sensitive decoding to finished runs.

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
