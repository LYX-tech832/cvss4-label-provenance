# Second encoder: does the gain of the v3.1 auxiliary task depend on the encoder? (temporal split, generated automatically)


## ehsanaghaei/SecureBERT

Configurations selected on the validation set (seed 0): baseline --epochs 5 --class_weight inv_sqrt (0.6885); auxiliary --epochs 5 --class_weight inv_sqrt --aux_v31 --aux_lambda 1 (0.7009).
Validation scores of the candidates: baseline {"e5_inv_sqrt": 0.6885, "e5_none": 0.6813, "e10_inv_sqrt": 0.6866, "e10_none": 0.6839, "e25_inv_sqrt": 0.6842}; auxiliary {"e5_inv_sqrt_lam0.5": 0.6967, "e5_inv_sqrt_lam1": 0.7009, "e5_none_lam0.5": 0.6938, "e5_none_lam1": 0.6932}

| Variant | Seeds | Scope | Mean macro-F1 (mean ± sd) | Band accuracy | Underestimation | MAE |
|---|---|---|---|---|---|---|
| baseline | [0, 1, 2, 3, 4] | all | 0.639 ± 0.002 | 0.615 | 0.149 | 1.237 |
| baseline | [0, 1, 2, 3, 4] | non-derived | 0.579 ± 0.002 | 0.528 | 0.170 | 1.394 |
| with v3.1 auxiliary | [0, 1, 2, 3, 4] | all | 0.652 ± 0.003 | 0.635 | 0.148 | 1.143 |
| with v3.1 auxiliary | [0, 1, 2, 3, 4] | non-derived | 0.599 ± 0.005 | 0.553 | 0.171 | 1.280 |

Gain (auxiliary − baseline; seeds [0, 1, 2, 3, 4]; paired bootstrap, 1,000 resamples, 95% interval):

| Scope | Mean macro-F1 | Band accuracy | Underestimation | Per-seed mean macro-F1 difference |
|---|---|---|---|---|
| all | +0.013 [+0.011, +0.015] | +0.020 [+0.017, +0.023] | -0.001 [-0.003, +0.002] | +0.010, +0.009, +0.017, +0.013, +0.016 |
| non-derived | +0.020 [+0.018, +0.022] | +0.024 [+0.020, +0.029] | +0.001 [-0.003, +0.004] | +0.024, +0.013, +0.024, +0.019, +0.021 |

## microsoft/deberta-v3-base

Configurations selected on the validation set (seed 0): baseline --epochs 25 --class_weight inv_sqrt (0.6769); auxiliary --epochs 5 --class_weight inv_sqrt --aux_v31 --aux_lambda 0.5 (0.6948).
Validation scores of the candidates: baseline {"e5_inv_sqrt": 0.6646, "e5_none": 0.663, "e10_inv_sqrt": 0.6702, "e10_none": 0.6766, "e25_inv_sqrt": 0.6769}; auxiliary {"e5_inv_sqrt_lam0.5": 0.6948, "e5_inv_sqrt_lam1": 0.6925, "e5_none_lam0.5": 0.6887, "e5_none_lam1": 0.6878}

| Variant | Seeds | Scope | Mean macro-F1 (mean ± sd) | Band accuracy | Underestimation | MAE |
|---|---|---|---|---|---|---|
| baseline | [0, 1, 2, 3, 4] | all | 0.620 ± 0.004 | 0.604 | 0.157 | 1.269 |
| baseline | [0, 1, 2, 3, 4] | non-derived | 0.564 ± 0.008 | 0.513 | 0.184 | 1.439 |
| with v3.1 auxiliary | [0, 1, 2, 3, 4] | all | 0.645 ± 0.002 | 0.623 | 0.143 | 1.174 |
| with v3.1 auxiliary | [0, 1, 2, 3, 4] | non-derived | 0.590 ± 0.005 | 0.537 | 0.165 | 1.321 |

Gain (auxiliary − baseline; seeds [0, 1, 2, 3, 4]; paired bootstrap, 1,000 resamples, 95% interval):

| Scope | Mean macro-F1 | Band accuracy | Underestimation | Per-seed mean macro-F1 difference |
|---|---|---|---|---|
| all | +0.025 [+0.023, +0.026] | +0.019 [+0.016, +0.022] | -0.014 [-0.016, -0.011] | +0.021, +0.023, +0.022, +0.032, +0.024 |
| non-derived | +0.026 [+0.024, +0.028] | +0.024 [+0.020, +0.029] | -0.018 [-0.021, -0.015] | +0.021, +0.021, +0.016, +0.043, +0.029 |

**Comparison**: gain in mean macro-F1, SecureBERT +0.013, DeBERTa-v3-base +0.025.

## Comparison with the TF-IDF pipeline (rule R, no v4.0 labels): model − pipeline (averaged over seeds; paired bootstrap, 1,000 resamples, 95% interval)

The two DeBERTa rows are a check: the point estimates should equal Table S33 of the paper; the intervals may differ by 0.001 because of a different random-number sequence.

| Model | Scope | Mean macro-F1 | Band accuracy | Underestimation |
|---|---|---|---|---|
| SecureBERT baseline | all | +0.074 [+0.070, +0.078] | +0.074 [+0.068, +0.082] | +0.022 [+0.017, +0.026] |
| SecureBERT baseline | non-derived | +0.033 [+0.029, +0.037] | -0.011 [-0.018, -0.003] | +0.021 [+0.015, +0.026] |
| SecureBERT with v3.1 auxiliary | all | +0.087 [+0.083, +0.091] | +0.095 [+0.088, +0.101] | +0.021 [+0.017, +0.025] |
| SecureBERT with v3.1 auxiliary | non-derived | +0.053 [+0.049, +0.057] | +0.014 [+0.006, +0.021] | +0.021 [+0.016, +0.026] |
| deberta-v3-base baseline | all | +0.055 [+0.051, +0.058] | +0.064 [+0.057, +0.070] | +0.030 [+0.026, +0.034] |
| deberta-v3-base baseline | non-derived | +0.017 [+0.013, +0.022] | -0.026 [-0.034, -0.019] | +0.034 [+0.029, +0.039] |
| deberta-v3-base with v3.1 auxiliary | all | +0.080 [+0.076, +0.083] | +0.083 [+0.076, +0.089] | +0.016 [+0.012, +0.021] |
| deberta-v3-base with v3.1 auxiliary | non-derived | +0.043 [+0.040, +0.047] | -0.001 [-0.009, +0.005] | +0.016 [+0.011, +0.021] |

## Comparison with the DeBERTa pipeline (no v4.0 labels, averaged over seeds 0–2): model with v3.1 auxiliary − DeBERTa pipeline

Point estimates of the pipeline (for checking, Section 7.2: mean macro-F1 0.601, underestimation rate 0.111, non-derived band accuracy 0.561): all mean macro-F1 0.601, band accuracy 0.622, underestimation rate 0.111; non-derived mean macro-F1 0.565, band accuracy 0.561, underestimation rate 0.126.

| Model | Scope | Mean macro-F1 | Band accuracy | Underestimation |
|---|---|---|---|---|
| SecureBERT with v3.1 auxiliary | all | +0.051 [+0.048, +0.054] | +0.013 [+0.008, +0.017] | +0.037 [+0.034, +0.041] |
| SecureBERT with v3.1 auxiliary | non-derived | +0.034 [+0.031, +0.037] | -0.009 [-0.015, -0.003] | +0.045 [+0.041, +0.048] |
| deberta-v3-base with v3.1 auxiliary | all | +0.043 [+0.040, +0.046] | +0.001 [-0.003, +0.006] | +0.033 [+0.030, +0.036] |
| deberta-v3-base with v3.1 auxiliary | non-derived | +0.024 [+0.021, +0.027] | -0.024 [-0.029, -0.018] | +0.039 [+0.035, +0.042] |
