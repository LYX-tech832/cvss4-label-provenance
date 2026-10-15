# Sensitivity to the TF-IDF settings; three-seed row of Table S14 (generated automatically)

## A. TF-IDF settings and the ranking reversal (temporal split; 21,900 test labels, 16,749 non-derived)

The classifier is trained on 14,488 and validated on 1,609 CVEs, then retrained on all 16,097; the first stage of the pipeline is trained on 99,472 and validated on 11,052 CVEs of the v3.1 corpus, then retrained on all 110,524.

### Classifier (TF-IDF + LR, v4.0 labels; minimum document frequency 2, at most 200,000 features)

| C | Mean validation macro-F1 | Test: mean macro-F1 all / non-derived | Test: band accuracy all / non-derived |
|---|---|---|---|
| 0.25 | 0.5711 | 0.530 / 0.468 | 0.530 / 0.418 |
| 1 | 0.6257 | 0.581 / 0.518 | 0.575 / 0.474 |
| 4 (paper) | 0.6613 | 0.605 / 0.547 | 0.598 / 0.504 |
| 16 | 0.6675 | 0.613 / 0.557 | 0.609 / 0.519 |
| 64 | 0.6647 | 0.617 / 0.564 | 0.611 / 0.523 |
| 256 | 0.6648 | 0.615 / 0.564 | 0.611 / 0.524 |

### Pipeline (first stage TF-IDF + LR predicts v3.1, then conversion with rule R; minimum document frequency 3, at most 300,000 features)

| C | Validation: v3.1 mean macro-F1 | Test: mean macro-F1 all / non-derived | Test: band accuracy all / non-derived |
|---|---|---|---|
| 1 | 0.7789 | 0.557 / 0.535 | 0.554 / 0.538 |
| 4 (paper) | 0.7838 | 0.565 / 0.546 | 0.541 / 0.539 |
| 16 | 0.7807 | 0.560 / 0.542 | 0.527 / 0.531 |

### Band accuracy difference: classifier − pipeline, all / non-derived

| Classifier C vs pipeline C | 1 | 4 | 16 |
|---|---|---|---|
| 0.25 | -0.024 / -0.120 | -0.010 / -0.121 | +0.003 / -0.113 |
| 1 | +0.021 / -0.065 | +0.034 / -0.065 | +0.048 / -0.058 |
| 4 | +0.044 / -0.034 | +0.057 / -0.035 | +0.071 / -0.027 |
| 16 | +0.055 / -0.020 | +0.068 / -0.020 | +0.082 / -0.013 |
| 64 | +0.057 / -0.015 | +0.071 / -0.016 | +0.084 / -0.008 |
| 256 | +0.057 / -0.015 | +0.071 / -0.015 | +0.084 / -0.008 |

Over the 18 combinations: the difference on all labels ranges from -0.024 to +0.084, on the non-derived labels from -0.121 to -0.008; positive on all labels in 16, negative on the non-derived labels in 18.

Settings selected on each side's validation set (classifier C = 16, pipeline C = 4): band accuracy difference all +0.068 [+0.061, +0.076], non-derived -0.020 [-0.029, -0.012] (paired bootstrap, 1,000 resamples). Mean macro-F1 difference: all +0.048, non-derived +0.011.

### LLM sample (2,000 CVEs): mean macro-F1 DeepSeek-V4-Pro − classifier (paired bootstrap stratified by label type, 1,000 resamples)

| Classifier C | Whole sample | Non-derived (1,700) |
|---|---|---|
| 0.25 | +0.034 [+0.020, +0.046] | +0.094 [+0.079, +0.108] |
| 1 | -0.010 [-0.024, +0.005] | +0.050 [+0.036, +0.066] |
| 4 (paper) | -0.031 [-0.047, -0.015] | +0.021 [+0.006, +0.039] |
| 16 | -0.042 [-0.057, -0.027] | +0.008 [-0.007, +0.024] |
| 64 | -0.047 [-0.061, -0.032] | +0.001 [-0.013, +0.017] |
| 256 | -0.044 [-0.059, -0.030] | +0.001 [-0.014, +0.017] |

### Feature settings swapped (C = 4)

| Setting | Test: band accuracy all / non-derived | Classifier − pipeline (all / non-derived) |
|---|---|---|
| paper's settings (classifier 2 / 200,000, pipeline 3 / 300,000) | classifier 0.598 / 0.504; pipeline 0.541 / 0.539 | +0.057 / -0.035 |
| classifier with 3 / 300,000 | classifier 0.601 / 0.507; pipeline 0.541 / 0.539 | +0.060 / -0.032 |
| pipeline with 2 / 200,000 | classifier 0.598 / 0.504; pipeline 0.540 / 0.538 | +0.058 / -0.034 |
| both swapped | classifier 0.601 / 0.507; pipeline 0.540 / 0.538 | +0.061 / -0.031 |

## B. Additional row of Table S14: the auxiliary-task model (5 epochs), 5 seeds and seeds 0–2

| Seeds | R-inc. (2,602) | No v3.1 (8,823) | R-inc., no VulnCheck (704) | AT:P predicted as None | AT macro-F1 (R-inc.) |
|---|---|---|---|---|---|
| 0–4 (the row already in the table) | 0.588 / 0.549 | 0.575 / 0.491 | 0.615 / 0.548 | 0.627 | 0.627 |
| 0–2 | 0.583 / 0.544 | 0.575 / 0.494 | 0.610 / 0.541 | 0.633 | 0.623 |
