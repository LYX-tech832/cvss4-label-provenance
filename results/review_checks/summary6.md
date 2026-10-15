# Calibration of the functional-dependence test, source characteristics, vendor-cluster resampling and decision-oriented metrics (generated automatically)

## A. Calibration of the functional-dependence test (sources with at least 100 dual-scored CVEs before 2026)

| Source | Pairs | FD_oos (observed) | Most-frequent-vector baseline | Permutation null mean / 95th percentile | Detection rate with synthetic conversion + noise p=0 / 0.05 / 0.10 / 0.20 (50 times) |
|---|---|---|---|---|---|
| VulDB | 7,731 | 0.930 | 0.221 | 0.255 / 0.268 | 1.00 / 1.00 / 0.94 / 0.00 |
| siemens | 523 | 0.771 | 0.076 | 0.069 / 0.102 | 0.00 / 0.00 / 0.00 / 0.00 |
| intel | 424 | 0.477 | 0.250 | 0.108 / 0.149 | 0.00 / 0.00 / 0.00 / 0.00 |
| icscert | 401 | 0.661 | 0.074 | 0.038 / 0.074 | 0.00 / 0.00 / 0.00 / 0.00 |
| VulnCheck | 236 | 0.408 | 0.056 | 0.116 / 0.183 | 1.00 / 0.90 / 0.28 / 0.00 |
| juniper | 199 | 0.517 | 0.083 | 0.066 / 0.117 | 0.00 / 0.00 / 0.00 / 0.00 |
| twcert | 117 | 0.833 | 0.194 | 0.163 / 0.250 | 0.00 / 0.00 / 0.00 / 0.00 |
| ABB | 105 | 0.375 | 0.000 | 0.008 / 0.031 | 0.00 / 0.00 / 0.00 / 0.00 |

Detection rate by sample size (synthetic conversion, no noise; n of the source's dual-scored CVEs before 2026; 50 random subsamples, each kept in time order)

| v3.1 vectors from | n=100 | n=200 | n=500 | n=1,000 | n=2,000 |
|---|---|---|---|---|---|
| VulDB (7,731 in total) | 0.90 | 0.98 | 1.00 | 1.00 | 1.00 |
| VulnCheck (236 in total) | 0.92 | 1.00 | — | — | — |
| siemens (523 in total) | 0.02 | 0.00 | 0.00 | — | — |
| intel (424 in total) | 0.00 | 0.00 | — | — | — |

## B. Source characteristics (all v4.0 labels)

| Source | n | Distinct v4 vectors | Normalised entropy of the vector distribution | Share of the most frequent vector | Median words per description | Share with a CWE | Distinct CWEs | Share of the top 3 CWEs |
|---|---|---|---|---|---|---|---|---|
| VulDB (derived) | 12,882 | 142 | 0.56 | 24.3% | 59 | 100.0% | 224 | 49.9% |
| VulnCheck | 7,429 | 753 | 0.73 | 8.3% | 51 | 99.9% | 306 | 23.9% |
| GitHub_M (v4-only) | 5,129 | 1,039 | 0.81 | 4.8% | 80 | 100.0% | 306 | 20.7% |
| other independent sources | 2,725 | 682 | 0.80 | 7.2% | 42 | 99.9% | 297 | 14.0% |
| other v4-only sources | 1,671 | 500 | 0.84 | 6.2% | 52 | 99.9% | 185 | 37.9% |
| other | 8,161 | 2,075 | 0.85 | 3.2% | 44 | 98.4% | 426 | 16.1% |

Results of each source (at least 200 CVEs) in the temporal split test set: mean macro-F1 / band accuracy

| Source | Type | n | Majority | TF-IDF | DeBERTa | DeBERTa + auxiliary |
|---|---|---|---|---|---|---|
| VulnCheck | independent | 6,388 | 0.262 / 0.346 | 0.535 / 0.563 | 0.524 / 0.513 | 0.577 / 0.586 |
| VulDB | derived | 5,151 | 0.317 / 0.806 | 0.624 / 0.904 | 0.629 / 0.897 | 0.643 / 0.903 |
| GitHub_M | v4_only | 3,600 | 0.259 / 0.383 | 0.454 / 0.415 | 0.481 / 0.382 | 0.534 / 0.467 |
| icscert | independent | 378 | 0.269 / 0.249 | 0.481 / 0.550 | 0.482 / 0.508 | 0.519 / 0.570 |
| EEF | other | 303 | 0.250 / 0.347 | 0.433 / 0.330 | 0.479 / 0.383 | 0.529 / 0.445 |
| CERT-PL | v4_only | 265 | 0.259 / 0.547 | 0.528 / 0.479 | 0.513 / 0.435 | 0.565 / 0.512 |
| Joomla | other | 243 | 0.268 / 0.379 | 0.395 / 0.457 | 0.415 / 0.435 | 0.459 / 0.511 |
| jpcert | other | 238 | 0.256 / 0.458 | 0.577 / 0.630 | 0.559 / 0.601 | 0.595 / 0.641 |
| mongodb | other | 200 | 0.253 / 0.355 | 0.462 / 0.560 | 0.440 / 0.450 | 0.496 / 0.534 |

## C. Resampling by vendor cluster (temporal split test set)

Test CVEs with vendor information 21,116 / 21,900; clusters 5,753; largest cluster 563 CVEs (openclaw).

| Comparison | Scope | Difference | 95% interval, resampling CVEs | 95% interval, resampling vendor clusters |
|---|---|---|---|---|
| aux − none (mean_macro_f1) | all | +0.039 | [+0.037, +0.041] | [+0.035, +0.044] |
| aux − none (band_acc) | all | +0.054 | [+0.051, +0.058] | [+0.048, +0.060] |
| aux − tfidf (mean_macro_f1) | all | +0.039 | [+0.036, +0.043] | [+0.032, +0.047] |
| aux − none (mean_macro_f1) | non-derived | +0.056 | [+0.054, +0.058] | [+0.051, +0.060] |
| aux − none (band_acc) | non-derived | +0.069 | [+0.064, +0.074] | [+0.063, +0.076] |
| aux − tfidf (mean_macro_f1) | non-derived | +0.043 | [+0.039, +0.046] | [+0.034, +0.052] |

LLM sample (2,000 CVEs): mean macro-F1 difference DeepSeek − TF-IDF; cluster resampling by vendor within each label type

| Scope | Difference | 95% interval, CVEs (within types) | 95% interval, vendor clusters (within types) |
|---|---|---|---|
| whole sample | -0.031 | [-0.046, -0.017] | [-0.054, -0.009] |
| non-derived | +0.021 | [+0.006, +0.037] | [+0.002, +0.040] |

Another macro-F1 (averaged only over the values present in the labels or predictions): the methods on the LLM sample

| Method | Whole sample | Non-derived | derived | independent | v4-only | other |
|---|---|---|---|---|---|---|
| DeepSeek-V4-Pro | 0.547 | 0.557 | 0.466 | 0.565 | 0.536 | 0.556 |
| TF-IDF + LR | 0.579 | 0.536 | 0.623 | 0.566 | 0.473 | 0.532 |
| DeBERTa + auxiliary (5 seeds) | 0.628 | 0.586 | 0.652 | 0.599 | 0.553 | 0.575 |

With this macro-F1, DeepSeek − TF-IDF: whole sample -0.031 [-0.047, -0.015]; non-derived +0.021 [+0.006, +0.039].

Temporal split test set, the other macro-F1: all / non-derived

| Method | All | Non-derived |
|---|---|---|
| TF-IDF | 0.605 | 0.547 |
| DeBERTa | 0.605 | 0.534 |
| DeBERTa + auxiliary | 0.645 | 0.590 |

## D. Decision-oriented metrics of risk-sensitive decoding (DeBERTa + auxiliary, temporal split test set, mean over 5 seeds)

| Decoding | Band accuracy | Underestimation | Overestimation | H+C precision | H+C recall | Escalation rate (predicted H/C) | Errors of two or more bands |
|---|---|---|---|---|---|---|---|
| argmax | 0.623 | 0.143 | 0.233 | 0.754 | 0.816 | 0.532 | 0.076 |
| α selected on validation data | 0.581 | 0.075 | 0.343 | 0.700 | 0.900 | 0.633 | 0.092 |
| α = 0.9 | 0.621 | 0.132 | 0.247 | 0.746 | 0.829 | 0.547 | 0.075 |
| α = 0.8 | 0.617 | 0.119 | 0.264 | 0.737 | 0.845 | 0.563 | 0.075 |
| α = 0.7 | 0.612 | 0.107 | 0.282 | 0.729 | 0.859 | 0.580 | 0.076 |
| α = 0.6 | 0.603 | 0.095 | 0.302 | 0.719 | 0.875 | 0.599 | 0.079 |
| α = 0.5 | 0.592 | 0.083 | 0.326 | 0.708 | 0.891 | 0.619 | 0.085 |
| α = 0.4 | 0.577 | 0.070 | 0.353 | 0.696 | 0.907 | 0.641 | 0.095 |
| α = 0.3 | 0.555 | 0.057 | 0.387 | 0.683 | 0.925 | 0.666 | 0.109 |

Share of High/Critical among the true labels: 0.492

Expected cost (r per underestimate, 1 per overestimate; test values at each α; DeBERTa + auxiliary averaged over 5 seeds; TF-IDF and the pipeline from the scan in risk_baselines)

| Method | α with the lowest cost at r = 1 | r = 2 | r = 5 | r = 10 |
|---|---|---|---|---|
| DeBERTa + auxiliary | α = 1.0 (cost 0.377; argmax 0.377) | α = 0.5 (cost 0.491; argmax 0.520) | α = 0.3 (cost 0.675; argmax 0.950) | α = 0.3 (cost 0.962; argmax 1.666) |
| TF-IDF | α = 1.0 (cost 0.402; argmax 0.402) | α = 0.6 (cost 0.507; argmax 0.538) | α = 0.3 (cost 0.656; argmax 0.948) | α = 0.3 (cost 0.830; argmax 1.630) |
| pipeline (rule R) | α = 1.0 (cost 0.459; argmax 0.459) | α = 0.8 (cost 0.582; argmax 0.586) | α = 0.3 (cost 0.754; argmax 0.967) | α = 0.3 (cost 0.918; argmax 1.602) |
