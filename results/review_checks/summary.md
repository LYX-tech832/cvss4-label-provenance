# Robustness checks (first set, generated automatically)


## (a) Fallbacks of FD_oos and confidence intervals

Fallback = share of v3.1 vectors in the test segment (the last 30%) not seen in the training segment. Three fallbacks: rule R (used in the paper) / the most frequent v4 vector of the training segment / none (seen vectors only). 
Intervals are Wilson 95% intervals with the rule-R fallback.


### all data

| CNA | Pairs | Test segment n | Fallback rate | FD_oos (rule-R fallback) | 95% interval | FD_oos (most-frequent fallback) | FD_oos (seen only) | Typing at 0.90 changes with the fallback |
|---|---|---|---|---|---|---|---|---|
| VulDB | 12,882 | 3865 | 5.0% | 99.5% | [99.3%, 99.7%] | 94.5% | 99.5% | no |
| VulnCheck | 6,304 | 1892 | 7.0% | 74.6% | [72.6%, 76.5%] | 70.9% | 76.0% | no |
| icscert | 728 | 219 | 31.1% | 77.2% | [71.2%, 82.2%] | 53.4% | 77.5% | no |
| siemens | 619 | 186 | 34.9% | 74.7% | [68.0%, 80.4%] | 52.2% | 80.2% | no |
| intel | 460 | 138 | 30.4% | 49.3% | [41.1%, 57.5%] | 41.3% | 59.4% | no |
| juniper | 273 | 82 | 17.1% | 76.8% | [66.6%, 84.6%] | 70.7% | 85.3% | no |
| twcert | 257 | 78 | 20.5% | 92.3% | [84.2%, 96.4%] | 75.6% | 95.2% | **yes** |
| mongodb | 209 | 63 | 39.7% | 46.0% | [34.3%, 58.2%] | 36.5% | 60.5% | no |
| f5 | 182 | 55 | 29.1% | 76.4% | [63.7%, 85.6%] | 61.8% | 87.2% | no |
| AMZN | 181 | 55 | 40.0% | 43.6% | [31.4%, 56.7%] | 36.4% | 60.6% | no |
| cisa-cg | 171 | 52 | 44.2% | 59.6% | [46.1%, 71.8%] | 36.5% | 65.5% | no |
| ABB | 129 | 39 | 76.9% | 43.6% | [29.3%, 59.0%] | 7.7% | 33.3% | no |
| jpcert | 128 | 39 | 28.2% | 71.8% | [56.2%, 83.5%] | 53.8% | 75.0% | no |
| CERTVDE | 103 | 31 | 35.5% | 77.4% | [60.2%, 88.6%] | 54.8% | 85.0% | no |

### before 2026 (typing window)

| CNA | Pairs | Test segment n | Fallback rate | FD_oos (rule-R fallback) | 95% interval | FD_oos (most-frequent fallback) | FD_oos (seen only) | Typing at 0.90 changes with the fallback |
|---|---|---|---|---|---|---|---|---|
| VulDB | 7,731 | 2320 | 0.6% | 93.0% | [91.9%, 93.9%] | 92.3% | 92.9% | no |
| siemens | 523 | 157 | 35.0% | 77.1% | [69.9%, 83.0%] | 54.1% | 83.3% | no |
| intel | 424 | 128 | 32.0% | 47.7% | [39.2%, 56.3%] | 39.1% | 57.5% | no |
| icscert | 401 | 121 | 38.8% | 66.1% | [57.3%, 73.9%] | 43.8% | 71.6% | no |
| VulnCheck | 236 | 71 | 1.4% | 40.8% | [30.2%, 52.5%] | 40.8% | 41.4% | no |
| juniper | 199 | 60 | 61.7% | 51.7% | [39.3%, 63.8%] | 33.3% | 87.0% | no |
| twcert | 117 | 36 | 22.2% | 83.3% | [68.1%, 92.1%] | 75.0% | 96.4% | **yes** |
| ABB | 105 | 32 | 68.8% | 37.5% | [22.9%, 54.7%] | 15.6% | 50.0% | no |

## (b) The R-inconsistent subset: dual-scored and v4.0 ≠ rule R(v3.1)

Temporal split test set: all 21,900; non-derived 16,749; R-inconsistent subset 2,602 (of which derived labels 3).

| Method | Scope | n | Mean macro-F1 | Band accuracy |
|---|---|---|---|---|
| TF-IDF + LR | all | 21,900 | 0.605 | 0.598 |
| DeBERTa + v3.1 auxiliary (mean of 5 seeds) | all | 21,900 | 0.645 | 0.623 |
| TF-IDF + LR | non-derived | 16,749 | 0.547 | 0.504 |
| DeBERTa + v3.1 auxiliary (mean of 5 seeds) | non-derived | 16,749 | 0.590 | 0.537 |
| TF-IDF + LR | R-inconsistent subset | 2,602 | 0.549 | 0.533 |
| DeBERTa + v3.1 auxiliary (mean of 5 seeds) | R-inconsistent subset | 2,602 | 0.588 | 0.549 |

## (c) AutoCVSS post-processing: DONT_KNOW → most frequent training value (the same 2,000 CVEs; paired bootstrap within types, 1,000 resamples)

(CVE, metric) pairs with DONT_KNOW or a failed request: 2,028 (9.2%).

| Scope | n | DeepSeek as in AutoCVSS macro-F1 / band | DeepSeek most frequent macro-F1 / band | TF-IDF macro-F1 / band | (most frequent − TF-IDF) macro-F1 difference [95%] | Band accuracy difference [95%] |
|---|---|---|---|---|---|---|
| whole sample | 2,000 | 0.547 / 0.417 | 0.573 / 0.473 | 0.579 / 0.554 | -0.005 [-0.020, +0.008] | -0.081 [-0.107, -0.051] |
| without derived | 1,700 | 0.557 / 0.459 | 0.563 / 0.473 | 0.536 / 0.496 | +0.027 [+0.012, +0.043] | -0.023 [-0.055, +0.005] |
| independent | 700 | 0.565 / 0.501 | 0.567 / 0.506 | 0.566 / 0.567 | +0.001 [-0.021, +0.027] | -0.061 [-0.110, -0.016] |
| v4_only | 500 | 0.536 / 0.414 | 0.542 / 0.434 | 0.473 / 0.430 | +0.069 [+0.042, +0.093] | +0.004 [-0.054, +0.054] |
| other | 500 | 0.556 / 0.444 | 0.566 / 0.466 | 0.532 / 0.462 | +0.033 [+0.005, +0.064] | +0.004 [-0.052, +0.064] |
| derived | 300 | 0.445 / 0.180 | 0.498 / 0.477 | 0.578 / 0.883 | -0.080 [-0.104, -0.052] | -0.407 [-0.473, -0.340] |

R-inconsistent subset of the sample (n = 261): DeepSeek (as in AutoCVSS) macro-F1 0.528 / band 0.483; TF-IDF 0.537 / 0.571; macro-F1 difference -0.008 [-0.053, +0.016].

## (d) Monotonicity of CVSS v4.0 scoring (all base vectors, each metric made one step more severe)

(vector, metric) combinations checked: 743,580; with a lower score: 0 (by metric: none); with a lower band: 0 (by metric: none).

## (e) Sources of the labels in the v3.1 auxiliary pool (before 2026)

110,524 in total: from CNA containers 80,350 (72.7%), from ADP containers 30,174 (27.3%).

## (f) Seeds on which the auxiliary variant wins, within each split (mean macro-F1, all test labels)

| Split | Winning seeds / 5 | Difference per seed |
|---|---|---|
| temporal | 5 / 5 | +0.038, +0.042, +0.035, +0.039, +0.044 |
| loso-VulnCheck | 5 / 5 | +0.023, +0.031, +0.029, +0.028, +0.021 |
| loso-GitHub_M | 5 / 5 | +0.011, +0.014, +0.013, +0.028, +0.017 |
| loso-VulDB | 4 / 5 | -0.002, +0.014, +0.027, +0.061, +0.004 |

## (g) Upper bound of temporal leakage (record-level update time; a record update is not necessarily a change of the v4.0 vector, hence an upper bound)

- v4 samples published before 2026 (training + validation parts of the temporal split): 16,097, of which 1,946 with a record updated after the start of 2026 (12.1%); 
- of these, dual-scored (used for the typing): 10,396, updated after the start of 2026 954 (9.2%); 
- by source (share updated after the start of 2026, sources with at least 500 v4 samples in the training part): VulnCheck 71.3%; siemens 7.6%; VulDB 6.2%; GitHub_M 4.0%
