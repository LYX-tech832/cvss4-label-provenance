# Rows of Tables 2, S24 and 3 (configurations selected on each split's own validation set; generated automatically)

## Table 2: the two DeBERTa rows (mean) and Table S24 (standard deviation)


### Temporal, all (baseline `_e25_cwinv_sqrt`, auxiliary `_aux_e5_cwinv_sqrt`)

mean | DeBERTa | 0.620 | 0.549 | 0.208 | 1.269 | 0.604 | 0.157 | 0.807 |
sd   | DeBERTa | 0.004 | 0.002 | 0.008 | 0.073 | 0.007 | 0.016 | 0.024 |
mean | DeBERTa + v3.1 aux. | 0.645 | 0.563 | 0.237 | 1.174 | 0.623 | 0.143 | 0.816 |
sd   | DeBERTa + v3.1 aux. | 0.002 | 0.005 | 0.004 | 0.023 | 0.003 | 0.011 | 0.019 |

### Temporal, non_derived (baseline `_e25_cwinv_sqrt`, auxiliary `_aux_e5_cwinv_sqrt`)

mean | DeBERTa | 0.564 | 0.533 | 0.134 | 1.439 | 0.513 | 0.184 | 0.816 |
sd   | DeBERTa | 0.008 | 0.003 | 0.009 | 0.094 | 0.010 | 0.021 | 0.026 |
mean | DeBERTa + v3.1 aux. | 0.590 | 0.547 | 0.165 | 1.321 | 0.537 | 0.165 | 0.826 |
sd   | DeBERTa + v3.1 aux. | 0.005 | 0.006 | 0.004 | 0.028 | 0.003 | 0.014 | 0.021 |

### LOSO–VulnCheck, all (baseline `_e16_cwinv_sqrt`, auxiliary `_aux_lam1_e5_cwinv_sqrt`)

mean | DeBERTa | 0.586 | 0.549 | 0.180 | 1.068 | 0.593 | 0.154 | 0.853 |
sd   | DeBERTa | 0.009 | 0.009 | 0.009 | 0.031 | 0.012 | 0.008 | 0.016 |
mean | DeBERTa + v3.1 aux. | 0.610 | 0.581 | 0.215 | 0.984 | 0.598 | 0.119 | 0.888 |
sd   | DeBERTa + v3.1 aux. | 0.004 | 0.005 | 0.011 | 0.019 | 0.014 | 0.017 | 0.019 |

### LOSO–GitHub, all (baseline `_e15_cwinv_sqrt`, auxiliary `_aux_lam1_e5_cwinv_sqrt`)

mean | DeBERTa | 0.522 | 0.490 | 0.082 | 1.588 | 0.466 | 0.256 | 0.720 |
sd   | DeBERTa | 0.004 | 0.005 | 0.010 | 0.066 | 0.012 | 0.033 | 0.049 |
mean | DeBERTa + v3.1 aux. | 0.547 | 0.516 | 0.107 | 1.445 | 0.494 | 0.185 | 0.803 |
sd   | DeBERTa + v3.1 aux. | 0.004 | 0.004 | 0.002 | 0.053 | 0.013 | 0.023 | 0.039 |

### LOSO–VulDB, all (baseline `_e5_cwinv_sqrt`, auxiliary `_aux_lam1_e5_cwinv_sqrt`)

mean | DeBERTa | 0.382 | 0.336 | 0.010 | 2.472 | 0.266 | 0.021 | 0.934 |
sd   | DeBERTa | 0.016 | 0.028 | 0.006 | 0.198 | 0.047 | 0.009 | 0.038 |
mean | DeBERTa + v3.1 aux. | 0.408 | 0.361 | 0.014 | 2.527 | 0.252 | 0.022 | 0.958 |
sd   | DeBERTa + v3.1 aux. | 0.012 | 0.019 | 0.005 | 0.210 | 0.056 | 0.014 | 0.028 |

## Table 3: risk-sensitive decoding (selected configuration of the auxiliary-task model, mean over 5 seeds; Over = 1 − Band − Under, from unrounded values)

| Temporal | argmax | 0.645 | 0.623 | 0.143 | 0.233 | 0.816 | 1.174 |
| Temporal | risk-sensitive | 0.632 | 0.581 | 0.075 | 0.343 | 0.900 | 1.202 |
(α: 0.5, 0.4, 0.5, 0.5, 0.3)
| LOSO–VulnCheck | argmax | 0.610 | 0.598 | 0.119 | 0.283 | 0.888 | 0.984 |
| LOSO–VulnCheck | risk-sensitive | 0.596 | 0.524 | 0.056 | 0.420 | 0.952 | 1.096 |
(α: 0.5, 0.5, 0.5, 0.4, 0.5)
| LOSO–GitHub | argmax | 0.547 | 0.494 | 0.185 | 0.321 | 0.803 | 1.445 |
| LOSO–GitHub | risk-sensitive | 0.532 | 0.441 | 0.083 | 0.476 | 0.914 | 1.487 |
(α: 0.4, 0.5, 0.5, 0.5, 0.4)
| LOSO–VulDB | argmax | 0.408 | 0.252 | 0.022 | 0.726 | 0.958 | 2.527 |
| LOSO–VulDB | risk-sensitive | 0.391 | 0.178 | 0.008 | 0.813 | 0.984 | 2.815 |
(α: 0.6, 0.5, 0.6, 0.6, 0.6)

## Quoted in the text: temporal split, auxiliary 5 epochs − baseline 25 epochs, differences in underestimation rate and MAE (paired bootstrap)

- all: mean_macro_f1 +0.025 [+0.023, +0.026]; band_acc +0.019 [+0.016, +0.022]; under_rate -0.014 [-0.016, -0.011]; score_mae -0.095 [-0.105, -0.085]
- non_derived: mean_macro_f1 +0.026 [+0.024, +0.028]; band_acc +0.024 [+0.020, +0.029]; under_rate -0.018 [-0.021, -0.015]; score_mae -0.118 [-0.130, -0.105]
