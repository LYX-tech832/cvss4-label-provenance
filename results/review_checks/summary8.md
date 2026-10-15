# Base-rate correction, training-side experiment and rolling time cut-offs (generated automatically)

## A. Base-rate correction: severity bands (temporal split test set)

Base rate = share of the most frequent band among the group's true bands (the band accuracy of always guessing that band). κ = unweighted Cohen's κ of the bands. DeBERTa averaged over 5 seeds.

| Group | n | Base rate | TF-IDF + LR: accuracy / above base rate / κ | DeBERTa (25 epochs, 5 seeds): accuracy / above base rate / κ | DeBERTa + auxiliary (5 seeds): accuracy / above base rate / κ |
|---|---|---|---|---|---|
| all | 21,900 | 0.469 | 0.598 / +0.129 / 0.386 | 0.604 / +0.135 / 0.388 | 0.623 / +0.154 / 0.415 |
| non-derived | 16,749 | 0.458 | 0.504 / +0.046 / 0.252 | 0.513 / +0.055 / 0.265 | 0.537 / +0.080 / 0.302 |
| type derived | 5,151 | 0.806 | 0.904 / +0.097 / 0.674 | 0.901 / +0.095 / 0.676 | 0.903 / +0.097 / 0.673 |
| type independent | 7,242 | 0.499 | 0.572 / +0.072 / 0.326 | 0.572 / +0.073 / 0.332 | 0.594 / +0.094 / 0.371 |
| type v4_only | 4,264 | 0.416 | 0.436 / +0.020 / 0.190 | 0.457 / +0.041 / 0.205 | 0.482 / +0.067 / 0.234 |
| type other | 5,243 | 0.434 | 0.466 / +0.032 / 0.203 | 0.477 / +0.043 / 0.222 | 0.504 / +0.070 / 0.262 |
| source VulDB | 5,151 | 0.806 | 0.904 / +0.097 / 0.674 | 0.901 / +0.095 / 0.676 | 0.903 / +0.097 / 0.673 |
| source VulnCheck | 6,388 | 0.502 | 0.563 / +0.061 / 0.313 | 0.562 / +0.060 / 0.318 | 0.586 / +0.084 / 0.359 |
| source GitHub_M | 3,600 | 0.433 | 0.415 / -0.019 / 0.161 | 0.438 / +0.005 / 0.178 | 0.467 / +0.034 / 0.213 |

## B. VulDB's labels removed from the training set (TF-IDF + LR; same test set)

Training labels: all 16,097; without VulDB 8,366 (VulDB 7,731, 48.0%).

| Test scope | n | Trained on all: mean macro-F1 / band accuracy | Trained without VulDB | Difference (without − all): mean macro-F1 | Band accuracy |
|---|---|---|---|---|---|
| non-derived | 16,749 | 0.547 / 0.504 | 0.544 / 0.497 | -0.002 [-0.004, -0.001] | -0.007 [-0.011, -0.002] |
| derived (VulDB) | 5,151 | 0.624 / 0.904 | 0.349 / 0.136 | -0.275 [-0.283, -0.266] | -0.768 [-0.782, -0.754] |
| type independent | 7,242 | 0.580 / 0.572 | 0.576 / 0.571 | -0.004 [-0.007, -0.001] | -0.001 [-0.007, +0.005] |
| type v4_only | 4,264 | 0.488 / 0.436 | 0.486 / 0.424 | -0.002 [-0.005, +0.001] | -0.011 [-0.021, -0.002] |
| type other | 5,243 | 0.524 / 0.466 | 0.523 / 0.455 | -0.002 [-0.004, +0.001] | -0.011 [-0.018, -0.003] |
| source VulnCheck | 6,388 | 0.535 / 0.563 | 0.532 / 0.561 | -0.003 [-0.006, -0.001] | -0.001 [-0.008, +0.005] |
| source GitHub_M | 3,600 | 0.454 / 0.415 | 0.451 / 0.402 | -0.003 [-0.008, +0.001] | -0.013 [-0.024, -0.003] |

## C. Rolling time cut-offs (TF-IDF + LR; trained on the labels before the cut-off date, tested on the following quarter)

| Cut-off date | Training | Test | Share of VulDB in the test set | All: mean macro-F1 / band accuracy | Without VulDB | Difference in band accuracy |
|---|---|---|---|---|---|---|
| 2025-07-01 | 8,731 | 3,747 | 50.3% | 0.673 / 0.745 | 0.589 / 0.536 | +0.209 |
| 2025-10-01 | 12,478 | 3,619 | 32.5% | 0.660 / 0.692 | 0.594 / 0.572 | +0.120 |
| 2026-01-01 | 16,097 | 5,775 | 24.7% | 0.641 / 0.632 | 0.579 / 0.532 | +0.099 |
| 2026-04-01 | 21,872 | 6,792 | 27.9% | 0.641 / 0.653 | 0.582 / 0.560 | +0.093 |
| 2026-07-01 | 28,664 | 9,333 | 19.6% | 0.612 / 0.603 | 0.568 / 0.533 | +0.070 |
