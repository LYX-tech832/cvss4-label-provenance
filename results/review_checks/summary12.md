# Further controls (generated automatically)

## A. Each source trained on only 1,000 of its own labels (TF-IDF + LR; mean of 5 random draws), tested on its own labels of 2026

| Source | v4.0 labels before 2026 | Test labels | Labels | Base rate | Band accuracy | κ | Mean macro-F1 |
|---|---|---|---|---|---|---|---|
| VulDB | 7,731 | 5,151 | v4.0 | 0.806 | 0.897 | 0.628 | 0.547 |
| VulDB | 7,731 | 5,151 | v3.1 | 0.487 | 0.606 | 0.336 | 0.667 |
| VulnCheck | 1,041 | 6,388 | v4.0 | 0.502 | 0.490 | 0.264 | 0.494 |
| GitHub_M | 1,529 | 3,600 | v4.0 | 0.433 | 0.337 | 0.100 | 0.410 |

(VulDB's v3.1 row: the same 1,000 CVEs, with their own v3.1 vectors as labels; macro-F1 averaged over the 8 v3.1 metrics.)

## B. Complete test set: models that predict v4.0 directly − pipelines without v4.0 labels (paired bootstrap, 1,000 resamples)

Point estimates of the pipelines (for checking, should match Table 2): pipeline (rule R) all 0.565 / 0.541, non-derived 0.546 / 0.539; pipeline (SC/SI/SA=N) all 0.519 / 0.545, non-derived 0.498 / 0.545 (mean macro-F1 / band accuracy).

| A − B | Scope | Mean macro-F1 | Band accuracy | Underestimation |
|---|---|---|---|---|
| TF-IDF − pipeline (rule R) | all | +0.040 [+0.036, +0.044] | +0.057 [+0.050, +0.065] | +0.009 [+0.004, +0.014] |
| TF-IDF − pipeline (rule R) | non-derived | +0.001 [-0.004, +0.005] | -0.035 [-0.044, -0.026] | +0.006 [-0.000, +0.011] |
| DeBERTa − pipeline (rule R) | all | +0.055 [+0.051, +0.059] | +0.064 [+0.057, +0.070] | +0.030 [+0.026, +0.034] |
| DeBERTa − pipeline (rule R) | non-derived | +0.017 [+0.014, +0.021] | -0.026 [-0.033, -0.019] | +0.034 [+0.029, +0.039] |
| DeBERTa+auxiliary − pipeline (rule R) | all | +0.080 [+0.076, +0.083] | +0.083 [+0.076, +0.090] | +0.016 [+0.012, +0.020] |
| DeBERTa+auxiliary − pipeline (rule R) | non-derived | +0.043 [+0.040, +0.047] | -0.001 [-0.008, +0.005] | +0.016 [+0.011, +0.021] |
| DeBERTa+auxiliary − pipeline (SC/SI/SA=N) | all | +0.126 [+0.123, +0.130] | +0.078 [+0.071, +0.085] | +0.012 [+0.007, +0.016] |
| DeBERTa+auxiliary − pipeline (SC/SI/SA=N) | non-derived | +0.091 [+0.088, +0.095] | -0.007 [-0.015, -0.000] | +0.010 [+0.004, +0.015] |

## C. VulnCheck's quarterly agreement with rule R: new vulnerabilities and back-filled old ones (identifier year at least two years before the publication year) separately

| Quarter | All: n / agreement | New: n / agreement | Back-filled: n / agreement |
|---|---|---|---|
| 2025Q4 | 235 / 40.4% | 21 / 52.4% | 214 / 39.3% |
| 2026Q1 | 1,464 / 53.6% | 385 / 52.7% | 1,079 / 53.8% |
| 2026Q2 | 1,643 / 67.1% | 1,061 / 60.3% | 582 / 79.6% |
| 2026Q3 | 2,961 / 77.1% | 2,893 / 76.8% | 68 / 89.7% |

## D. All pairwise comparisons on the 2,000-CVE sample: opposite signs of the pooled and the non-derived differences

| A − B | Metric | Pooled [95%] | Non-derived [95%] | Opposite signs | Neither interval contains 0 |
|---|---|---|---|---|---|
| DeepSeek − majority class | band accuracy | -0.025 [-0.055, +0.006] | +0.085 [+0.051, +0.118] | yes | no |
| DeepSeek − TF-IDF | mean macro-F1 | -0.031 [-0.046, -0.017] | +0.021 [+0.005, +0.038] | yes | yes |
| DeepSeek − pipeline (rule R) | mean macro-F1 | -0.006 [-0.019, +0.009] | +0.021 [+0.007, +0.037] | yes | no |
| TF-IDF − pipeline (rule R) | mean macro-F1 | +0.026 [+0.014, +0.039] | -0.000 [-0.013, +0.013] | yes | no |
| TF-IDF − pipeline (rule R) | band accuracy | +0.016 [-0.007, +0.040] | -0.034 [-0.059, -0.008] | yes | no |
| pipeline (rule R) − DeBERTa | band accuracy | -0.032 [-0.053, -0.013] | +0.018 [-0.005, +0.040] | yes | no |
| pipeline (rule R) − DeBERTa+auxiliary | band accuracy | -0.045 [-0.066, -0.026] | +0.004 [-0.019, +0.025] | yes | no |

42 (method pair × metric) in total; 7 with opposite signs, of which 1 with neither interval containing 0. Only those with opposite signs are listed.
