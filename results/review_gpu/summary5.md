# Step-matched baselines on the leave-one-source-out splits, sequential fine-tuning, shuffled-label control and the earliest 5% of the labels (GPU runs; generated automatically)

## 1. Leave-one-source-out splits: step-matched baselines (D0 / D1)

| Split | Candidate configurations (mean validation macro-F1, seed 0) | Selected baseline configuration | Best epoch of the step-matched candidate |
|---|---|---|---|
| loso:VulnCheck | `_e5_cwinv_sqrt` 0.6384; `_e5` 0.6311; `_e10_cwinv_sqrt` 0.6477; `_e10` 0.6482; `_e16_cwinv_sqrt` 0.6488 | `_e16_cwinv_sqrt` | 9 |
| loso:GitHub_M | `_e5_cwinv_sqrt` 0.6523; `_e5` 0.6451; `_e10_cwinv_sqrt` 0.6566; `_e10` 0.6501; `_e15_cwinv_sqrt` 0.6606 | `_e15_cwinv_sqrt` | 13 |
| loso:VulDB | `_e5_cwinv_sqrt` 0.6252; `_e5` 0.5920; `_e10_cwinv_sqrt` 0.6251; `_e10` 0.6222; `_e18_cwinv_sqrt` 0.6252 | `_e5_cwinv_sqrt` | 7 |

### loso:VulnCheck

| Model | Seeds | Scope | Mean macro-F1 | Band accuracy | Underestimation | H+C recall |
|---|---|---|---|---|---|---|
| auxiliary `_aux_lam1_e5_cwinv_sqrt` | [0, 1, 2, 3, 4] | all | 0.610 ± 0.004 | 0.598 ± 0.014 | 0.119 ± 0.017 | 0.888 ± 0.019 |
| baseline (selected) `_e16_cwinv_sqrt` | [0, 1, 2, 3, 4] | all | 0.586 ± 0.009 | 0.593 ± 0.012 | 0.154 ± 0.008 | 0.853 ± 0.016 |
| baseline (step-matched) `_e16_cwinv_sqrt` | [0, 1, 2, 3, 4] | all | 0.586 ± 0.009 | 0.593 ± 0.012 | 0.154 ± 0.008 | 0.853 ± 0.016 |

loso:VulnCheck: auxiliary − baseline (step-matched) (common seeds [0, 1, 2, 3, 4])

| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |
|---|---|---|---|---|---|
| all | +0.025 [+0.022, +0.028] | +0.005 [-0.002, +0.010] | +0.018, +0.020, +0.019, +0.025, +0.043 | [+0.012, +0.038] | 5/5 |

### loso:GitHub_M

| Model | Seeds | Scope | Mean macro-F1 | Band accuracy | Underestimation | H+C recall |
|---|---|---|---|---|---|---|
| auxiliary `_aux_lam1_e5_cwinv_sqrt` | [0, 1, 2, 3, 4] | all | 0.547 ± 0.004 | 0.494 ± 0.013 | 0.185 ± 0.023 | 0.803 ± 0.039 |
| baseline (selected) `_e15_cwinv_sqrt` | [0, 1, 2, 3, 4] | all | 0.522 ± 0.004 | 0.466 ± 0.012 | 0.256 ± 0.033 | 0.720 ± 0.049 |
| baseline (step-matched) `_e15_cwinv_sqrt` | [0, 1, 2, 3, 4] | all | 0.522 ± 0.004 | 0.466 ± 0.012 | 0.256 ± 0.033 | 0.720 ± 0.049 |

loso:GitHub_M: auxiliary − baseline (step-matched) (common seeds [0, 1, 2, 3, 4])

| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |
|---|---|---|---|---|---|
| all | +0.025 [+0.021, +0.030] | +0.028 [+0.020, +0.035] | +0.029, +0.016, +0.026, +0.036, +0.020 | [+0.016, +0.035] | 5/5 |

### loso:VulDB

| Model | Seeds | Scope | Mean macro-F1 | Band accuracy | Underestimation | H+C recall |
|---|---|---|---|---|---|---|
| auxiliary `_aux_lam1_e5_cwinv_sqrt` | [0, 1, 2, 3, 4] | all | 0.408 ± 0.012 | 0.252 ± 0.056 | 0.022 ± 0.014 | 0.958 ± 0.028 |
| baseline (selected) `_e5_cwinv_sqrt` | [0, 1, 2, 3, 4] | all | 0.382 ± 0.016 | 0.266 ± 0.047 | 0.021 ± 0.009 | 0.934 ± 0.038 |
| baseline (step-matched) `_e18_cwinv_sqrt` | [0] | all | 0.388 ± nan | 0.269 ± nan | 0.049 ± nan | 0.874 ± nan |

loso:VulDB: auxiliary − baseline (step-matched) (common seeds [0])

| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |
|---|---|---|---|---|---|
| all | +0.026 [+0.022, +0.031] | +0.052 [+0.044, +0.059] | +0.026 | [+nan, +nan] | 1/1 |

loso:VulDB: auxiliary − baseline (selected) (common seeds [0, 1, 2, 3, 4])

| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |
|---|---|---|---|---|---|
| all | +0.026 [+0.024, +0.028] | -0.014 [-0.017, -0.010] | +0.020, +0.013, +0.020, +0.055, +0.023 | [+0.006, +0.047] | 5/5 |

## 2. Sequential fine-tuning baseline (A; temporal split)

Stage 1: the v3.1 heads are trained for 5 epochs on the 60,000 samples of the v3.1 pool only (as in the DeBERTa pipeline), and the encoder of the best validation epoch is kept; stage 2: starting from this encoder, fine-tuning on the v4 labels only (class weighting).

| Cap on stage-2 epochs | Mean validation macro-F1 (seed 0) | Best epoch |
|---|---|---|
| 5 | 0.6991 | 4 |
| 10 | 0.6978 | 3 |
| 25 | 0.7001 | 7 |

Selected on the validation set: 25 epochs.

| Model | Seeds | Scope | Mean macro-F1 | Band accuracy | Underestimation | H+C recall |
|---|---|---|---|---|---|---|
| baseline 25 epochs | [0, 1, 2] | all | 0.622 ± 0.002 | 0.606 ± 0.004 | 0.155 ± 0.014 | 0.805 ± 0.026 |
| baseline 25 epochs | [0, 1, 2] | non_derived | 0.568 ± 0.002 | 0.515 ± 0.007 | 0.181 ± 0.017 | 0.815 ± 0.028 |
| sequential fine-tuning (stage 2, 25 epochs) | [0, 1, 2] | all | 0.645 ± 0.005 | 0.627 ± 0.007 | 0.150 ± 0.015 | 0.822 ± 0.023 |
| sequential fine-tuning (stage 2, 25 epochs) | [0, 1, 2] | non_derived | 0.588 ± 0.006 | 0.542 ± 0.010 | 0.175 ± 0.019 | 0.832 ± 0.024 |
| v3.1 auxiliary 5 epochs | [0, 1, 2] | all | 0.644 ± 0.001 | 0.624 ± 0.003 | 0.137 ± 0.010 | 0.827 ± 0.007 |
| v3.1 auxiliary 5 epochs | [0, 1, 2] | non_derived | 0.587 ± 0.005 | 0.537 ± 0.003 | 0.157 ± 0.013 | 0.839 ± 0.007 |
| rule-R pseudo-labels 5 epochs | [0, 1, 2] | all | 0.643 ± 0.003 | 0.635 ± 0.006 | 0.130 ± 0.018 | 0.833 ± 0.026 |
| rule-R pseudo-labels 5 epochs | [0, 1, 2] | non_derived | 0.594 ± 0.000 | 0.552 ± 0.008 | 0.148 ± 0.022 | 0.845 ± 0.028 |

auxiliary − sequential fine-tuning (common seeds [0, 1, 2])

| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |
|---|---|---|---|---|---|
| all | -0.001 [-0.003, +0.001] | -0.003 [-0.007, +0.001] | +0.007, -0.004, -0.005 | [-0.017, +0.015] | 1/3 |
| non_derived | -0.001 [-0.003, +0.001] | -0.005 [-0.010, -0.001] | +0.006, -0.005, -0.003 | [-0.016, +0.014] | 1/3 |

sequential fine-tuning − baseline 25 epochs (common seeds [0, 1, 2])

| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |
|---|---|---|---|---|---|
| all | +0.023 [+0.021, +0.025] | +0.021 [+0.017, +0.024] | +0.015, +0.027, +0.027 | [+0.005, +0.041] | 3/3 |
| non_derived | +0.020 [+0.018, +0.023] | +0.028 [+0.022, +0.033] | +0.015, +0.026, +0.019 | [+0.006, +0.035] | 3/3 |

## 3. Shuffled-label control on the leave-one-source-out splits (B; seeds 0–2)


### loso:VulnCheck

| Model | Seeds | Scope | Mean macro-F1 | Band accuracy | Underestimation | H+C recall |
|---|---|---|---|---|---|---|
| baseline (selected) `_e16_cwinv_sqrt` | [0, 1, 2] | all | 0.589 ± 0.005 | 0.601 ± 0.004 | 0.155 ± 0.005 | 0.848 ± 0.005 |
| shuffled v3.1 labels `_auxshuf_lam1_e5_cwinv_sqrt` | [0, 1, 2] | all | 0.594 ± 0.005 | 0.587 ± 0.003 | 0.125 ± 0.013 | 0.883 ± 0.019 |
| correct v3.1 labels `_aux_lam1_e5_cwinv_sqrt` | [0, 1, 2] | all | 0.608 ± 0.004 | 0.589 ± 0.011 | 0.107 ± 0.006 | 0.901 ± 0.007 |

loso:VulnCheck: correct labels − shuffled labels (common seeds [0, 1, 2])

| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |
|---|---|---|---|---|---|
| all | +0.014 [+0.011, +0.018] | +0.002 [-0.005, +0.009] | +0.013, +0.011, +0.019 | [+0.003, +0.025] | 3/3 |

loso:VulnCheck: shuffled labels − baseline (selected) (common seeds [0, 1, 2])

| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |
|---|---|---|---|---|---|
| all | +0.004 [+0.001, +0.008] | -0.015 [-0.022, -0.008] | +0.005, +0.009, -0.001 | [-0.007, +0.016] | 2/3 |

### loso:GitHub_M

| Model | Seeds | Scope | Mean macro-F1 | Band accuracy | Underestimation | H+C recall |
|---|---|---|---|---|---|---|
| baseline (selected) `_e15_cwinv_sqrt` | [0, 1, 2] | all | 0.523 ± 0.004 | 0.466 ± 0.011 | 0.255 ± 0.046 | 0.728 ± 0.068 |
| shuffled v3.1 labels `_auxshuf_lam1_e5_cwinv_sqrt` | [0, 1, 2] | all | 0.533 ± 0.002 | 0.482 ± 0.014 | 0.228 ± 0.023 | 0.756 ± 0.025 |
| correct v3.1 labels `_aux_lam1_e5_cwinv_sqrt` | [0, 1, 2] | all | 0.546 ± 0.004 | 0.498 ± 0.016 | 0.193 ± 0.025 | 0.795 ± 0.048 |

loso:GitHub_M: correct labels − shuffled labels (common seeds [0, 1, 2])

| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |
|---|---|---|---|---|---|
| all | +0.013 [+0.009, +0.017] | +0.016 [+0.008, +0.024] | +0.014, +0.007, +0.019 | [-0.002, +0.028] | 3/3 |

loso:GitHub_M: shuffled labels − baseline (selected) (common seeds [0, 1, 2])

| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |
|---|---|---|---|---|---|
| all | +0.010 [+0.006, +0.015] | +0.016 [+0.008, +0.025] | +0.014, +0.009, +0.007 | [+0.000, +0.020] | 3/3 |

### loso:VulDB

| Model | Seeds | Scope | Mean macro-F1 | Band accuracy | Underestimation | H+C recall |
|---|---|---|---|---|---|---|
| baseline (selected) `_e5_cwinv_sqrt` | [0, 1, 2] | all | 0.385 ± 0.010 | 0.293 ± 0.038 | 0.026 ± 0.003 | 0.910 ± 0.027 |
| shuffled v3.1 labels `_auxshuf_lam1_e5_cwinv_sqrt` | [0, 1, 2] | all | 0.396 ± 0.009 | 0.307 ± 0.044 | 0.046 ± 0.007 | 0.842 ± 0.082 |
| correct v3.1 labels `_aux_lam1_e5_cwinv_sqrt` | [0, 1, 2] | all | 0.403 ± 0.014 | 0.256 ± 0.073 | 0.030 ± 0.010 | 0.944 ± 0.028 |

loso:VulDB: correct labels − shuffled labels (common seeds [0, 1, 2])

| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |
|---|---|---|---|---|---|
| all | +0.006 [+0.004, +0.009] | -0.051 [-0.056, -0.046] | +0.027, -0.018, +0.010 | [-0.050, +0.063] | 2/3 |

loso:VulDB: shuffled labels − baseline (selected) (common seeds [0, 1, 2])

| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |
|---|---|---|---|---|---|
| all | +0.011 [+0.009, +0.013] | +0.014 [+0.010, +0.018] | -0.007, +0.031, +0.009 | [-0.036, +0.058] | 2/3 |

## 4. The earliest 5% of the v4 training labels (C; seeds 0–2)

| Model | Seeds | Scope | Mean macro-F1 | Band accuracy | Underestimation | H+C recall |
|---|---|---|---|---|---|---|
| random 5%: baseline 50 epochs | [0, 1, 2] | all | 0.538 ± 0.008 | 0.500 ± 0.023 | 0.148 ± 0.024 | 0.833 ± 0.030 |
| random 5%: baseline 50 epochs | [0, 1, 2] | non_derived | 0.471 ± 0.011 | 0.385 ± 0.028 | 0.166 ± 0.035 | 0.848 ± 0.033 |
| random 5%: v3.1 auxiliary 5 epochs | [0, 1, 2] | all | 0.618 ± 0.004 | 0.609 ± 0.018 | 0.130 ± 0.023 | 0.837 ± 0.033 |
| random 5%: v3.1 auxiliary 5 epochs | [0, 1, 2] | non_derived | 0.562 ± 0.008 | 0.526 ± 0.020 | 0.146 ± 0.029 | 0.851 ± 0.034 |
| earliest 5%: baseline 50 epochs | [0, 1, 2] | all | 0.485 ± 0.008 | 0.485 ± 0.019 | 0.136 ± 0.022 | 0.860 ± 0.030 |
| earliest 5%: baseline 50 epochs | [0, 1, 2] | non_derived | 0.422 ± 0.006 | 0.394 ± 0.019 | 0.140 ± 0.026 | 0.893 ± 0.029 |
| earliest 5%: v3.1 auxiliary 5 epochs | [0, 1, 2] | all | 0.593 ± 0.004 | 0.568 ± 0.014 | 0.113 ± 0.016 | 0.869 ± 0.022 |
| earliest 5%: v3.1 auxiliary 5 epochs | [0, 1, 2] | non_derived | 0.551 ± 0.002 | 0.494 ± 0.008 | 0.125 ± 0.019 | 0.875 ± 0.021 |
| all labels: baseline 25 epochs | [0, 1, 2] | all | 0.622 ± 0.002 | 0.606 ± 0.004 | 0.155 ± 0.014 | 0.805 ± 0.026 |
| all labels: baseline 25 epochs | [0, 1, 2] | non_derived | 0.568 ± 0.002 | 0.515 ± 0.007 | 0.181 ± 0.017 | 0.815 ± 0.028 |

earliest 5%: auxiliary − baseline (common seeds [0, 1, 2])

| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |
|---|---|---|---|---|---|
| all | +0.109 [+0.106, +0.112] | +0.082 [+0.077, +0.088] | +0.121, +0.104, +0.102 | [+0.083, +0.134] | 3/3 |
| non_derived | +0.129 [+0.126, +0.132] | +0.100 [+0.093, +0.107] | +0.136, +0.124, +0.126 | [+0.113, +0.145] | 3/3 |

earliest 5% with auxiliary − all labels baseline 25 epochs (common seeds [0, 1, 2])

| Scope | Mean macro-F1 difference [bootstrap] | Band accuracy difference [bootstrap] | Per-seed differences (mean macro-F1) | t interval | Positive seeds |
|---|---|---|---|---|---|
| all | -0.028 [-0.031, -0.025] | -0.038 [-0.044, -0.033] | -0.027, -0.026, -0.031 | [-0.035, -0.022] | 0/3 |
| non_derived | -0.017 [-0.021, -0.014] | -0.021 [-0.026, -0.015] | -0.017, -0.018, -0.017 | [-0.018, -0.016] | 0/3 |

Earliest 5%: 724 labels, published from 2017-05-11 to 2024-07-01; sources: VulDB 57.5%, siemens 12.8%, icscert 5.9%, juniper 4.6%; label types: derived 57.5%, independent 24.0%, other 16.0%, v4_only 2.5%.
All training labels: 14,488, published from 2017-05-11 to 2025-11-21; sources: VulDB 49.6%, GitHub_M 9.3%, VulnCheck 4.1%, siemens 3.5%.
