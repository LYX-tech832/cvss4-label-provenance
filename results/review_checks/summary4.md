# Transfer gains on subsets where rule R cannot help (temporal split; generated automatically)

R-inconsistent subset = dual-scored and v4.0 ≠ rule R(same-source v3.1); of these, VulnCheck 1,898, derived 3.


## all (21,900): n = 21,900

| Variant | Seeds | Mean macro-F1 | Macro-F1 of the 7 shared metrics | Macro-F1 of AT/SC/SI/SA | Band accuracy |
|---|---|---|---|---|---|
| baseline 5 epochs | 5 | 0.605 | 0.643 | 0.540 | 0.569 |
| v3.1 auxiliary 5 epochs | 5 | 0.645 | 0.701 | 0.547 | 0.623 |
| baseline 10 epochs | 3 | 0.617 | 0.662 | 0.539 | 0.592 |
| v3.1 auxiliary 10 epochs | 3 | 0.645 | 0.701 | 0.545 | 0.631 |
| pseudo-labels 5 epochs | 3 | 0.643 | 0.697 | 0.549 | 0.635 |
| DeBERTa pipeline | 3 | 0.601 | 0.666 | 0.488 | 0.622 |
| TF-IDF | 1 | 0.605 | 0.668 | 0.496 | 0.598 |

Paired bootstrap (A − B, mean macro-F1 / band accuracy, 95% interval; when the two variants have different numbers of seeds, only the common seeds 0–2 are used):

| A − B | Mean macro-F1 difference | Band accuracy difference |
|---|---|---|
| v3.1 auxiliary 5 epochs − baseline 5 epochs | +0.039 [+0.037, +0.041] | +0.054 [+0.051, +0.058] |
| v3.1 auxiliary 10 epochs − baseline 10 epochs | +0.027 [+0.025, +0.030] | +0.039 [+0.035, +0.043] |
| pseudo-labels 5 epochs − baseline 5 epochs | +0.037 [+0.035, +0.040] | +0.066 [+0.062, +0.071] |
| v3.1 auxiliary 5 epochs − pseudo-labels 5 epochs | +0.001 [-0.001, +0.003] | -0.011 [-0.015, -0.008] |
| DeBERTa pipeline − baseline 5 epochs | -0.004 [-0.008, -0.001] | +0.054 [+0.049, +0.059] |

## R-inconsistent subset: n = 2,602

| Variant | Seeds | Mean macro-F1 | Macro-F1 of the 7 shared metrics | Macro-F1 of AT/SC/SI/SA | Band accuracy |
|---|---|---|---|---|---|
| baseline 5 epochs | 5 | 0.550 | 0.536 | 0.573 | 0.496 |
| v3.1 auxiliary 5 epochs | 5 | 0.588 | 0.597 | 0.573 | 0.549 |
| baseline 10 epochs | 3 | 0.556 | 0.551 | 0.566 | 0.519 |
| v3.1 auxiliary 10 epochs | 3 | 0.588 | 0.603 | 0.562 | 0.550 |
| pseudo-labels 5 epochs | 3 | 0.579 | 0.589 | 0.562 | 0.557 |
| DeBERTa pipeline | 3 | 0.535 | 0.562 | 0.487 | 0.542 |
| TF-IDF | 1 | 0.549 | 0.563 | 0.526 | 0.533 |

Paired bootstrap (A − B, mean macro-F1 / band accuracy, 95% interval; when the two variants have different numbers of seeds, only the common seeds 0–2 are used):

| A − B | Mean macro-F1 difference | Band accuracy difference |
|---|---|---|
| v3.1 auxiliary 5 epochs − baseline 5 epochs | +0.039 [+0.033, +0.045] | +0.053 [+0.042, +0.064] |
| v3.1 auxiliary 10 epochs − baseline 10 epochs | +0.032 [+0.026, +0.038] | +0.031 [+0.019, +0.044] |
| pseudo-labels 5 epochs − baseline 5 epochs | +0.029 [+0.021, +0.038] | +0.066 [+0.053, +0.079] |
| v3.1 auxiliary 5 epochs − pseudo-labels 5 epochs | +0.004 [-0.001, +0.009] | -0.013 [-0.024, -0.003] |
| DeBERTa pipeline − baseline 5 epochs | -0.015 [-0.024, -0.005] | +0.050 [+0.035, +0.066] |

## no same-source v3.1: n = 8,823

| Variant | Seeds | Mean macro-F1 | Macro-F1 of the 7 shared metrics | Macro-F1 of AT/SC/SI/SA | Band accuracy |
|---|---|---|---|---|---|
| baseline 5 epochs | 5 | 0.515 | 0.528 | 0.493 | 0.426 |
| v3.1 auxiliary 5 epochs | 5 | 0.575 | 0.612 | 0.511 | 0.491 |
| baseline 10 epochs | 3 | 0.537 | 0.560 | 0.496 | 0.445 |
| v3.1 auxiliary 10 epochs | 3 | 0.574 | 0.611 | 0.508 | 0.495 |
| pseudo-labels 5 epochs | 3 | 0.576 | 0.614 | 0.510 | 0.500 |
| DeBERTa pipeline | 3 | 0.541 | 0.597 | 0.443 | 0.505 |
| TF-IDF | 1 | 0.519 | 0.564 | 0.440 | 0.451 |

Paired bootstrap (A − B, mean macro-F1 / band accuracy, 95% interval; when the two variants have different numbers of seeds, only the common seeds 0–2 are used):

| A − B | Mean macro-F1 difference | Band accuracy difference |
|---|---|---|
| v3.1 auxiliary 5 epochs − baseline 5 epochs | +0.060 [+0.057, +0.064] | +0.066 [+0.059, +0.072] |
| v3.1 auxiliary 10 epochs − baseline 10 epochs | +0.037 [+0.034, +0.040] | +0.049 [+0.043, +0.057] |
| pseudo-labels 5 epochs − baseline 5 epochs | +0.058 [+0.054, +0.061] | +0.072 [+0.064, +0.080] |
| v3.1 auxiliary 5 epochs − pseudo-labels 5 epochs | -0.001 [-0.004, +0.001] | -0.006 [-0.012, +0.000] |
| DeBERTa pipeline − baseline 5 epochs | +0.023 [+0.018, +0.028] | +0.077 [+0.068, +0.087] |

## R-inconsistent subset without VulnCheck: n = 704

| Variant | Seeds | Mean macro-F1 | Macro-F1 of the 7 shared metrics | Macro-F1 of AT/SC/SI/SA | Band accuracy |
|---|---|---|---|---|---|
| baseline 5 epochs | 5 | 0.574 | 0.572 | 0.578 | 0.506 |
| v3.1 auxiliary 5 epochs | 5 | 0.615 | 0.640 | 0.573 | 0.548 |
| baseline 10 epochs | 3 | 0.576 | 0.586 | 0.558 | 0.543 |
| v3.1 auxiliary 10 epochs | 3 | 0.614 | 0.647 | 0.557 | 0.538 |
| pseudo-labels 5 epochs | 3 | 0.604 | 0.633 | 0.553 | 0.545 |
| DeBERTa pipeline | 3 | 0.533 | 0.596 | 0.422 | 0.511 |
| TF-IDF | 1 | 0.572 | 0.606 | 0.513 | 0.523 |

Paired bootstrap (A − B, mean macro-F1 / band accuracy, 95% interval; when the two variants have different numbers of seeds, only the common seeds 0–2 are used):

| A − B | Mean macro-F1 difference | Band accuracy difference |
|---|---|---|
| v3.1 auxiliary 5 epochs − baseline 5 epochs | +0.041 [+0.032, +0.051] | +0.042 [+0.020, +0.065] |
| v3.1 auxiliary 10 epochs − baseline 10 epochs | +0.038 [+0.028, +0.049] | -0.005 [-0.032, +0.020] |
| pseudo-labels 5 epochs − baseline 5 epochs | +0.031 [+0.019, +0.043] | +0.041 [+0.013, +0.068] |
| v3.1 auxiliary 5 epochs − pseudo-labels 5 epochs | +0.006 [-0.002, +0.014] | -0.004 [-0.025, +0.017] |
| DeBERTa pipeline − baseline 5 epochs | -0.040 [-0.056, -0.026] | +0.007 [-0.026, +0.040] |

## AT: the 1,034 labels of the R-inconsistent subset with AT:Present

| Variant | Seeds | Share predicted as AT:None | Macro-F1 of AT on the R-inconsistent subset |
|---|---|---|---|
| baseline 5 epochs | 5 | 0.545 | 0.644 |
| v3.1 auxiliary 5 epochs | 5 | 0.627 | 0.627 |
| baseline 10 epochs | 3 | 0.525 | 0.649 |
| v3.1 auxiliary 10 epochs | 3 | 0.656 | 0.603 |
| pseudo-labels 5 epochs | 3 | 0.860 | 0.495 |
| DeBERTa pipeline | 3 | 1.000 | 0.376 |
| TF-IDF | 1 | 0.919 | 0.456 |
| 5% + v3.1 auxiliary | 3 | 0.848 | 0.498 |

## 5% + auxiliary − all labels, baseline (10 epochs): mean macro-F1 difference (paired bootstrap, 1,000 resamples)

| Subset | n | Difference [95%] |
|---|---|---|
| R-inconsistent subset | 2,602 | -0.006 [-0.013, +0.001] |
| consistent with rule R (dual-scored, non-derived) | 5,327 | +0.035 [+0.029, +0.040] |
| consistent with rule R (dual-scored, including derived) | 10,475 | +0.018 [+0.013, +0.022] |
