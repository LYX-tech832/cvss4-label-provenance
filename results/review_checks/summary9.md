# Tables recomputed with the selected 25-epoch baseline (generated automatically)

## 1. Table 4 (LLM sample, 2,000 CVEs): mean macro-F1 / band accuracy

| Model | Whole sample | Non-derived | derived | undetected | v4-only | other |
|---|---|---|---|---|---|---|
| DeBERTa (25 epochs, 5 seeds) | 0.600 / 0.570 | 0.559 / 0.512 | 0.597 / 0.899 | 0.576 / 0.587 | 0.530 / 0.470 | 0.544 / 0.448 |
| DeBERTa (5 epochs, 5 seeds) | 0.587 / 0.519 | 0.534 / 0.452 | 0.590 / 0.901 | 0.561 / 0.517 | 0.509 / 0.398 | 0.503 / 0.414 |
| DeBERTa + auxiliary (5 seeds) | 0.628 / 0.583 | 0.586 / 0.526 | 0.603 / 0.904 | 0.599 / 0.591 | 0.553 / 0.495 | 0.575 / 0.467 |

## 2. Table S5: per-metric macro-F1 (all / non-derived), mean over 5 seeds

| Metric | DeBERTa 25 epochs | DeBERTa + auxiliary | Gain (all) |
|---|---|---|---|
| AV | 0.647 / 0.610 | 0.722 / 0.689 | +0.075 |
| AC | 0.670 / 0.593 | 0.681 / 0.594 | +0.011 |
| AT | 0.639 / 0.617 | 0.649 / 0.628 | +0.010 |
| PR | 0.608 / 0.622 | 0.664 / 0.689 | +0.056 |
| UI | 0.601 / 0.563 | 0.630 / 0.592 | +0.029 |
| VC | 0.711 / 0.578 | 0.731 / 0.602 | +0.020 |
| VI | 0.700 / 0.563 | 0.721 / 0.596 | +0.021 |
| VA | 0.741 / 0.568 | 0.756 / 0.580 | +0.015 |
| SC | 0.534 / 0.525 | 0.551 / 0.540 | +0.017 |
| SI | 0.544 / 0.536 | 0.563 / 0.554 | +0.019 |
| SA | 0.427 / 0.424 | 0.425 / 0.421 | -0.002 |

Mean gain on the 7 shared metrics (AV, AC, PR, UI, VC, VI, VA) +0.032; on the 4 new metrics (AT, SC, SI, SA) +0.011; largest two gains: AV +0.075, PR +0.056.

## 3. Additional rows of Table S11 (all labels, seeds 0–2)

| Model | AV | AC | AT | PR | UI | VC | VI | VA | SC | SI | SA |
|---|---|---|---|---|---|---|---|---|---|---|---|
| baseline 25 epochs | 0.659 | 0.670 | 0.633 | 0.617 | 0.602 | 0.710 | 0.705 | 0.736 | 0.535 | 0.543 | 0.428 |
| shuffled v3.1 labels 5 epochs | 0.665 | 0.669 | 0.651 | 0.607 | 0.607 | 0.713 | 0.707 | 0.748 | 0.554 | 0.562 | 0.426 |

## 4. DeBERTa (25 epochs) rows of Table S15: label-substitution control

| Scope | Band accuracy original → rule R | Difference [95%] | Underestimation original → rule R | Difference [95%] |
|---|---|---|---|---|
| all (7,926) | 0.560 → 0.569 | +0.010 [+0.005, +0.014] | 0.153 → 0.170 | +0.017 [+0.014, +0.020] |
| VulnCheck (6,068) | 0.562 → 0.576 | +0.014 [+0.009, +0.018] | 0.142 → 0.156 | +0.015 [+0.011, +0.018] |
| without VulnCheck (1,858) | 0.552 → 0.549 | -0.004 [-0.011, +0.004] | 0.191 → 0.216 | +0.024 [+0.017, +0.031] |

## 5. DeBERTa (25 epochs) column of Table S18: each source (at least 200 CVEs), mean macro-F1 / band accuracy

| Source | n | DeBERTa 25 epochs | DeBERTa + auxiliary | Auxiliary better (macro-F1) |
|---|---|---|---|---|
| VulnCheck | 6,388 | 0.551 / 0.562 | 0.577 / 0.586 | yes |
| VulDB | 5,151 | 0.638 / 0.901 | 0.643 / 0.903 | yes |
| GitHub_M | 3,600 | 0.508 / 0.438 | 0.534 / 0.467 | yes |
| icscert | 378 | 0.498 / 0.558 | 0.519 / 0.570 | yes |
| EEF | 303 | 0.512 / 0.364 | 0.529 / 0.445 | yes |
| CERT-PL | 265 | 0.552 / 0.500 | 0.565 / 0.512 | yes |
| Joomla | 243 | 0.424 / 0.485 | 0.459 / 0.511 | yes |
| jpcert | 238 | 0.597 / 0.618 | 0.595 / 0.641 | no |
| mongodb | 200 | 0.478 / 0.486 | 0.496 / 0.534 | yes |

Sources where the auxiliary model has the higher mean macro-F1: 8.

## 6. Table S21: vendor clusters (baseline = 25 epochs without the auxiliary task)

| Comparison | Scope | Difference | Resampling CVEs | Resampling vendor clusters |
|---|---|---|---|---|
| aux − none25 (mean_macro_f1) | all | +0.025 | [+0.023, +0.026] | [+0.021, +0.028] |
| aux − none25 (band_acc) | all | +0.019 | [+0.016, +0.023] | [+0.015, +0.024] |
| aux − tfidf (mean_macro_f1) | all | +0.039 | [+0.036, +0.043] | [+0.032, +0.047] |
| aux − none25 (mean_macro_f1) | non-derived | +0.026 | [+0.024, +0.028] | [+0.022, +0.030] |
| aux − none25 (band_acc) | non-derived | +0.024 | [+0.020, +0.028] | [+0.019, +0.030] |
| aux − tfidf (mean_macro_f1) | non-derived | +0.043 | [+0.039, +0.047] | [+0.035, +0.052] |

## 7. Note of Table S22: macro-F1 averaged only over the values present (temporal split test set, all / non-derived)

| Method | All | Non-derived |
|---|---|---|
| TF-IDF | 0.605 | 0.547 |
| DeBERTa 25 epochs | 0.620 | 0.564 |
| DeBERTa + auxiliary | 0.645 | 0.590 |
