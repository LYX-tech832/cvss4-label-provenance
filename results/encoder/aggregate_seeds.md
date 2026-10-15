# Multi-seed summary (baseline configuration 'e5_cwinv_sqrt'; auxiliary configuration 'e5_cwinv_sqrt', λ = 0.5)


## Scope: all test labels

| Split | Variant | Seeds | mean_macro_f1 | exact_match | score_mae | band_acc | under_rate | hc_recall |
|---|---|---|---|---|---|---|---|---|
| loso-GitHub_M | aux | 5 | 0.542±0.004 | 0.108±0.003 | 1.451±0.032 | 0.493±0.006 | 0.191±0.011 | 0.798±0.029 |
| loso-GitHub_M | none | 5 | 0.525±0.007 | 0.085±0.007 | 1.576±0.054 | 0.462±0.013 | 0.198±0.025 | 0.802±0.034 |
| loso-VulDB | aux | 5 | 0.402±0.014 | 0.013±0.004 | 2.483±0.261 | 0.257±0.081 | 0.024±0.016 | 0.947±0.031 |
| loso-VulDB | none | 5 | 0.382±0.016 | 0.010±0.006 | 2.472±0.198 | 0.266±0.047 | 0.021±0.009 | 0.934±0.038 |
| loso-VulnCheck | aux | 5 | 0.607±0.004 | 0.215±0.012 | 0.986±0.013 | 0.601±0.008 | 0.125±0.008 | 0.878±0.012 |
| loso-VulnCheck | none | 5 | 0.581±0.003 | 0.181±0.012 | 1.070±0.016 | 0.579±0.010 | 0.131±0.007 | 0.884±0.009 |
| temporal | aux | 5 | 0.645±0.002 | 0.237±0.004 | 1.174±0.023 | 0.623±0.003 | 0.143±0.011 | 0.816±0.019 |
| temporal | none | 5 | 0.605±0.002 | 0.188±0.011 | 1.444±0.054 | 0.569±0.006 | 0.159±0.011 | 0.827±0.016 |

Descriptive summary: differences (auxiliary − baseline) over all (split, seed) pairs, 20 pairs (no significance test, see Section 5.5):
| Metric | Mean difference | Pairs with difference > 0 |
|---|---|---|
| mean_macro_f1 | +0.0258 | 19/20 |
| exact_match | +0.0272 | 18/20 |
| score_mae | -0.1166 | 3/20 |
| band_acc | +0.0246 | 17/20 |
| under_rate | -0.0064 | 7/20 |
| hc_recall | -0.0022 | 8/20 |

Mean difference per split (mean F1 / band accuracy / underestimation rate): loso-GitHub_M: +0.017 / +0.031 / -0.007 (5 pairs); loso-VulDB: +0.021 / -0.009 / +0.003 (5 pairs); loso-VulnCheck: +0.026 / +0.022 / -0.006 (5 pairs); temporal: +0.039 / +0.054 / -0.016 (5 pairs)

## Scope: without derived labels

| Split | Variant | Seeds | mean_macro_f1 | exact_match | score_mae | band_acc | under_rate | hc_recall |
|---|---|---|---|---|---|---|---|---|
| loso-GitHub_M | aux | 5 | 0.542±0.004 | 0.108±0.003 | 1.451±0.032 | 0.493±0.006 | 0.191±0.011 | 0.798±0.029 |
| loso-GitHub_M | none | 5 | 0.525±0.007 | 0.085±0.007 | 1.576±0.054 | 0.462±0.013 | 0.198±0.025 | 0.802±0.034 |
| loso-VulnCheck | aux | 5 | 0.607±0.004 | 0.215±0.012 | 0.986±0.013 | 0.601±0.008 | 0.125±0.008 | 0.878±0.012 |
| loso-VulnCheck | none | 5 | 0.581±0.003 | 0.181±0.012 | 1.070±0.016 | 0.579±0.010 | 0.131±0.007 | 0.884±0.009 |
| temporal | aux | 5 | 0.590±0.005 | 0.165±0.004 | 1.321±0.028 | 0.537±0.003 | 0.165±0.014 | 0.826±0.021 |
| temporal | none | 5 | 0.534±0.004 | 0.112±0.013 | 1.660±0.070 | 0.468±0.008 | 0.184±0.015 | 0.839±0.017 |

Descriptive summary: differences (auxiliary − baseline) over all (split, seed) pairs, 15 pairs (no significance test, see Section 5.5):
| Metric | Mean difference | Pairs with difference > 0 |
|---|---|---|
| mean_macro_f1 | +0.0330 | 15/15 |
| exact_match | +0.0365 | 15/15 |
| score_mae | -0.1824 | 0/15 |
| band_acc | +0.0406 | 15/15 |
| under_rate | -0.0104 | 6/15 |
| hc_recall | -0.0076 | 4/15 |

Mean difference per split (mean F1 / band accuracy / underestimation rate): loso-GitHub_M: +0.017 / +0.031 / -0.007 (5 pairs); loso-VulnCheck: +0.026 / +0.022 / -0.006 (5 pairs); temporal: +0.056 / +0.069 / -0.018 (5 pairs)

## Paired bootstrap within each split (auxiliary − baseline; averaged over seeds first; 1000 resamples; 95% percentile interval)

| Split | Scope | n | Seeds (baseline/aux) | Mean macro-F1 difference | Band accuracy difference | Underestimation difference | Score MAE difference |
|---|---|---|---|---|---|---|---|
| loso-GitHub_M | all | 5,129 | 5/5 | +0.017 [+0.013, +0.020] | +0.031 [+0.023, +0.038] | -0.007 [-0.012, -0.002] | -0.125 [-0.146, -0.103] |
| loso-GitHub_M | without derived | 5,129 | 5/5 | +0.017 [+0.013, +0.020] | +0.031 [+0.024, +0.038] | -0.007 [-0.012, -0.002] | -0.125 [-0.148, -0.103] |
| loso-VulDB | all | 12,882 | 5/5 | +0.021 [+0.019, +0.023] | -0.009 [-0.012, -0.005] | +0.003 [+0.002, +0.004] | +0.011 [+0.002, +0.022] |
| loso-VulnCheck | all | 7,429 | 5/5 | +0.026 [+0.023, +0.029] | +0.022 [+0.016, +0.027] | -0.006 [-0.010, -0.002] | -0.084 [-0.098, -0.068] |
| loso-VulnCheck | without derived | 7,429 | 5/5 | +0.026 [+0.023, +0.029] | +0.022 [+0.016, +0.028] | -0.006 [-0.010, -0.002] | -0.084 [-0.100, -0.069] |
| temporal | all | 21,900 | 5/5 | +0.039 [+0.037, +0.041] | +0.054 [+0.051, +0.058] | -0.016 [-0.018, -0.013] | -0.269 [-0.283, -0.256] |
| temporal | without derived | 16,749 | 5/5 | +0.056 [+0.054, +0.058] | +0.069 [+0.064, +0.074] | -0.018 [-0.022, -0.014] | -0.339 [-0.354, -0.323] |

An interval that excludes 0 indicates a stable difference on that split. Lower underestimation rate and MAE are better, so a negative difference in these two columns is an improvement.