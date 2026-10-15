# Configuration selection, step-matched baselines and timing sensitivity (GPU runs; generated automatically)

## 1. Configuration selected on each split's own validation set (seed 0)

| Split | Auxiliary model | Baseline |
|---|---|---|
| temporal | `_aux_e5_cwinv_sqrt` (0.6948) | `_e25_cwinv_sqrt` (0.6769) |
| loso:VulnCheck | `_aux_lam1_e5_cwinv_sqrt` (0.6653) | `_e16_cwinv_sqrt` (0.6488) |
| loso:GitHub_M | `_aux_lam1_e5_cwinv_sqrt` (0.6738) | `_e15_cwinv_sqrt` (0.6606) |
| loso:VulDB | `_aux_lam1_e5_cwinv_sqrt` (0.6416) | `_e5_cwinv_sqrt` (0.6252) |

## 2. Main results of the selected configurations (as in Table 2; mean ± standard deviation, seeds 0–4)


### temporal, all

| Model | Seeds | Macro-F1 | v4-F1 | Exact | MAE | Band | Under | H+C rec. |
|---|---|---|---|---|---|---|---|---|
| baseline `_e25_cwinv_sqrt` | 5 | 0.620 ± 0.004 | 0.549 ± 0.002 | 0.208 ± 0.008 | 1.269 ± 0.073 | 0.604 ± 0.007 | 0.157 ± 0.016 | 0.807 ± 0.024 |
| auxiliary `_aux_e5_cwinv_sqrt` | 5 | 0.645 ± 0.002 | 0.563 ± 0.005 | 0.237 ± 0.004 | 1.174 ± 0.023 | 0.623 ± 0.003 | 0.143 ± 0.011 | 0.816 ± 0.019 |

### temporal, non_derived

| Model | Seeds | Macro-F1 | v4-F1 | Exact | MAE | Band | Under | H+C rec. |
|---|---|---|---|---|---|---|---|---|
| baseline `_e25_cwinv_sqrt` | 5 | 0.564 ± 0.008 | 0.533 ± 0.003 | 0.134 ± 0.009 | 1.439 ± 0.094 | 0.513 ± 0.010 | 0.184 ± 0.021 | 0.816 ± 0.026 |
| auxiliary `_aux_e5_cwinv_sqrt` | 5 | 0.590 ± 0.005 | 0.547 ± 0.006 | 0.165 ± 0.004 | 1.321 ± 0.028 | 0.537 ± 0.003 | 0.165 ± 0.014 | 0.826 ± 0.021 |

temporal: auxiliary − baseline (selected configurations) (common seeds [0, 1, 2, 3, 4])

| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |
|---|---|---|---|---|---|
| all | +0.025 [+0.023, +0.026] | +0.019 [+0.016, +0.022] | +0.021, +0.023, +0.022, +0.032, +0.024 | [+0.019, +0.030] | 5/5 |
| non_derived | +0.026 [+0.024, +0.028] | +0.024 [+0.020, +0.029] | +0.021, +0.021, +0.016, +0.043, +0.029 | [+0.013, +0.039] | 5/5 |

### loso:VulnCheck, all

| Model | Seeds | Macro-F1 | v4-F1 | Exact | MAE | Band | Under | H+C rec. |
|---|---|---|---|---|---|---|---|---|
| baseline `_e16_cwinv_sqrt` | 5 | 0.586 ± 0.009 | 0.549 ± 0.009 | 0.180 ± 0.009 | 1.068 ± 0.031 | 0.593 ± 0.012 | 0.154 ± 0.008 | 0.853 ± 0.016 |
| auxiliary `_aux_lam1_e5_cwinv_sqrt` | 5 | 0.610 ± 0.004 | 0.581 ± 0.005 | 0.215 ± 0.011 | 0.984 ± 0.019 | 0.598 ± 0.014 | 0.119 ± 0.017 | 0.888 ± 0.019 |

loso:VulnCheck: auxiliary − baseline (selected configurations) (common seeds [0, 1, 2, 3, 4])

| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |
|---|---|---|---|---|---|
| all | +0.025 [+0.022, +0.028] | +0.005 [-0.002, +0.010] | +0.018, +0.020, +0.019, +0.025, +0.043 | [+0.012, +0.038] | 5/5 |

loso:VulnCheck: reference, configuration selected on the temporal split, auxiliary − baseline (common seeds [0, 1, 2, 3, 4])

| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |
|---|---|---|---|---|---|
| all | +0.026 [+0.023, +0.029] | +0.022 [+0.016, +0.027] | +0.023, +0.031, +0.029, +0.028, +0.021 | [+0.021, +0.032] | 5/5 |

### loso:GitHub_M, all

| Model | Seeds | Macro-F1 | v4-F1 | Exact | MAE | Band | Under | H+C rec. |
|---|---|---|---|---|---|---|---|---|
| baseline `_e15_cwinv_sqrt` | 5 | 0.522 ± 0.004 | 0.490 ± 0.005 | 0.082 ± 0.010 | 1.588 ± 0.066 | 0.466 ± 0.012 | 0.256 ± 0.033 | 0.720 ± 0.049 |
| auxiliary `_aux_lam1_e5_cwinv_sqrt` | 5 | 0.547 ± 0.004 | 0.516 ± 0.004 | 0.107 ± 0.002 | 1.445 ± 0.053 | 0.494 ± 0.013 | 0.185 ± 0.023 | 0.803 ± 0.039 |

loso:GitHub_M: auxiliary − baseline (selected configurations) (common seeds [0, 1, 2, 3, 4])

| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |
|---|---|---|---|---|---|
| all | +0.025 [+0.021, +0.030] | +0.028 [+0.020, +0.035] | +0.029, +0.016, +0.026, +0.036, +0.020 | [+0.016, +0.035] | 5/5 |

loso:GitHub_M: reference, configuration selected on the temporal split, auxiliary − baseline (common seeds [0, 1, 2, 3, 4])

| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |
|---|---|---|---|---|---|
| all | +0.017 [+0.013, +0.020] | +0.031 [+0.023, +0.038] | +0.011, +0.014, +0.013, +0.028, +0.017 | [+0.008, +0.025] | 5/5 |

### loso:VulDB, all

| Model | Seeds | Macro-F1 | v4-F1 | Exact | MAE | Band | Under | H+C rec. |
|---|---|---|---|---|---|---|---|---|
| baseline `_e5_cwinv_sqrt` | 5 | 0.382 ± 0.016 | 0.336 ± 0.028 | 0.010 ± 0.006 | 2.472 ± 0.198 | 0.266 ± 0.047 | 0.021 ± 0.009 | 0.934 ± 0.038 |
| auxiliary `_aux_lam1_e5_cwinv_sqrt` | 5 | 0.408 ± 0.012 | 0.361 ± 0.019 | 0.014 ± 0.005 | 2.527 ± 0.210 | 0.252 ± 0.056 | 0.022 ± 0.014 | 0.958 ± 0.028 |

loso:VulDB: auxiliary − baseline (selected configurations) (common seeds [0, 1, 2, 3, 4])

| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |
|---|---|---|---|---|---|
| all | +0.026 [+0.024, +0.028] | -0.014 [-0.017, -0.010] | +0.020, +0.013, +0.020, +0.055, +0.023 | [+0.006, +0.047] | 5/5 |

loso:VulDB: reference, configuration selected on the temporal split, auxiliary − baseline (common seeds [0, 1, 2, 3, 4])

| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |
|---|---|---|---|---|---|
| all | +0.021 [+0.019, +0.023] | -0.009 [-0.012, -0.005] | -0.002, +0.014, +0.027, +0.061, +0.004 | [-0.010, +0.052] | 4/5 |

## 3. Temporal split: auxiliary 5 epochs vs baselines trained for different lengths


Baseline 5 epochs: best epoch [4, 5, 5, 4, 5]

auxiliary 5 epochs − baseline 5 epochs (common seeds [0, 1, 2, 3, 4])

| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |
|---|---|---|---|---|---|
| all | +0.039 [+0.037, +0.041] | +0.054 [+0.051, +0.058] | +0.038, +0.042, +0.035, +0.039, +0.044 | [+0.035, +0.044] | 5/5 |
| non_derived | +0.056 [+0.054, +0.058] | +0.069 [+0.064, +0.074] | +0.054, +0.057, +0.043, +0.062, +0.063 | [+0.046, +0.066] | 5/5 |

Baseline 10 epochs: best epoch [6, 7, 8, 8, 6]

auxiliary 5 epochs − baseline 10 epochs (common seeds [0, 1, 2, 3, 4])

| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |
|---|---|---|---|---|---|
| all | +0.026 [+0.025, +0.028] | +0.030 [+0.027, +0.034] | +0.027, +0.028, +0.026, +0.026, +0.026 | [+0.026, +0.027] | 5/5 |
| non_derived | +0.035 [+0.033, +0.037] | +0.040 [+0.035, +0.044] | +0.041, +0.038, +0.023, +0.034, +0.039 | [+0.026, +0.043] | 5/5 |

Baseline 25 epochs (as many optimisation steps as auxiliary 5 epochs): best epoch [25, 19, 22, 6, 6]

auxiliary 5 epochs − baseline 25 epochs (as many optimisation steps as auxiliary 5 epochs) (common seeds [0, 1, 2, 3, 4])

| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |
|---|---|---|---|---|---|
| all | +0.025 [+0.023, +0.026] | +0.019 [+0.016, +0.022] | +0.021, +0.023, +0.022, +0.032, +0.024 | [+0.019, +0.030] | 5/5 |
| non_derived | +0.026 [+0.024, +0.028] | +0.024 [+0.020, +0.029] | +0.021, +0.021, +0.016, +0.043, +0.029 | [+0.013, +0.039] | 5/5 |

## 4. Timing sensitivity: without the CVEs whose containers were updated after the cut-off (seeds 0–2)

Removed: 1,946 v4 training/validation samples and 35,996 samples of the auxiliary pool; the test set is unchanged.

| Model | Scope | All data | Without them |
|---|---|---|---|
| baseline 10 epochs | all | 0.617 / 0.592 | 0.603 / 0.582 |
| baseline 10 epochs | non_derived | 0.553 / 0.496 | 0.537 / 0.485 |
| auxiliary 5 epochs | all | 0.644 / 0.624 | 0.644 / 0.616 |
| auxiliary 5 epochs | non_derived | 0.587 / 0.537 | 0.585 / 0.528 |

without them: auxiliary 5 epochs − baseline 10 epochs (common seeds [0, 1, 2])

| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |
|---|---|---|---|---|---|
| all | +0.041 [+0.039, +0.043] | +0.035 [+0.031, +0.039] | +0.039, +0.038, +0.046 | [+0.031, +0.051] | 3/3 |
| non_derived | +0.048 [+0.046, +0.050] | +0.042 [+0.037, +0.047] | +0.049, +0.040, +0.054 | [+0.030, +0.066] | 3/3 |

reference (all data, seeds 0–2): auxiliary 5 epochs − baseline 10 epochs (common seeds [0, 1, 2])

| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |
|---|---|---|---|---|---|
| all | +0.027 [+0.025, +0.029] | +0.032 [+0.028, +0.036] | +0.027, +0.028, +0.026 | [+0.025, +0.029] | 3/3 |
| non_derived | +0.034 [+0.032, +0.036] | +0.041 [+0.036, +0.046] | +0.041, +0.038, +0.023 | [+0.011, +0.057] | 3/3 |
