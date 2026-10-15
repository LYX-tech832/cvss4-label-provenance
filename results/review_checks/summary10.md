# Predictability by source, back-filling and source-macro averages (generated automatically)

## A. Predictability of the v3.1 and the v4.0 labels of the same CVEs (TF-IDF + LR; the dual-scored CVEs of T1)

Training: 10,396 dual-scored CVEs before 2026; test: 13,077 in 2026. Input, training CVEs and test CVEs are identical for both models; only the version of the labels differs.

| Source of the test labels | n | v3.1: base rate / band accuracy / κ / mean macro-F1 (8 metrics) | v4.0: base rate / band accuracy / κ / mean macro-F1 (11 metrics) |
|---|---|---|---|
| VulDB | 5,151 | 0.487 / 0.654 / 0.420 / 0.773 | 0.806 / 0.905 / 0.681 / 0.626 |
| all other sources | 7,926 | 0.468 / 0.525 / 0.276 / 0.618 | 0.512 / 0.566 / 0.299 / 0.546 |
| VulnCheck | 6,068 | 0.477 / 0.529 / 0.283 / 0.594 | 0.508 / 0.568 / 0.308 / 0.513 |
| other than VulDB and VulnCheck | 1,858 | 0.439 / 0.511 / 0.256 / 0.613 | 0.524 / 0.560 / 0.261 / 0.556 |

(Macro-F1 is averaged over all values of each metric; values that do not occur score 0, as in the paper.)

## B. CVE identifier years in the temporal split test set (published in 2026)

| Source | n | Identifier year < 2025 | Identifier year = 2025 | Identifier year = 2026 |
|---|---|---|---|---|
| VulnCheck | 6,388 | 27.3% | 2.2% | 70.5% |
| VulDB | 5,151 | 0.2% | 1.9% | 97.9% |
| GitHub_M | 3,600 | 0.2% | 3.4% | 96.4% |
| other sources | 6,761 | 1.0% | 13.0% | 86.0% |
| all | 21,900 | 8.4% | 5.7% | 86.0% |

## C. Source-macro averages (temporal split test set; equal weight per source)


Sources with at least 30 test CVEs: 60 (covering 20,550 / 21,900 CVEs)

| Method | Mean macro-F1 | Band accuracy | Underestimation |
|---|---|---|---|
| majority class | 0.249 | 0.373 | 0.577 |
| TF-IDF + LR | 0.466 | 0.507 | 0.173 |
| DeBERTa (25 epochs) | 0.488 | 0.516 | 0.208 |
| DeBERTa + auxiliary | 0.508 | 0.540 | 0.181 |

Auxiliary − DeBERTa (25 epochs), source-macro average: mean macro-F1 +0.019 [+0.015, +0.024] (sources resampled); sources where the auxiliary model is better 53 / 60; band accuracy +0.024 [+0.012, +0.037]. 
Auxiliary − TF-IDF, source-macro average: mean macro-F1 +0.042; sources where the auxiliary model is better 53 / 60.

Sources with at least 100 test CVEs: 22 (covering 18,563 / 21,900 CVEs)

| Method | Mean macro-F1 | Band accuracy | Underestimation |
|---|---|---|---|
| majority class | 0.255 | 0.433 | 0.487 |
| TF-IDF + LR | 0.480 | 0.523 | 0.135 |
| DeBERTa (25 epochs) | 0.507 | 0.526 | 0.172 |
| DeBERTa + auxiliary | 0.530 | 0.553 | 0.153 |

Auxiliary − DeBERTa (25 epochs), source-macro average: mean macro-F1 +0.023 [+0.016, +0.031] (sources resampled); sources where the auxiliary model is better 20 / 22; band accuracy +0.028 [+0.007, +0.055]. 
Auxiliary − TF-IDF, source-macro average: mean macro-F1 +0.050; sources where the auxiliary model is better 21 / 22.

## D. Label types of the T1 test set (2026, dual-scored)

independent 6,765; derived 5,151; other 1,161; total 13,077.
By definition, fewer than 5% of the CVEs of v4-only CNAs are dual-scored; their dual-scored CVEs in 2026: 0 ().

## E. Main results without the back-filled test CVEs (identifier year before 2025)

Removed: 1,829 (VulnCheck 1,747). Mean macro-F1 / band accuracy:

| Scope | n | TF-IDF + LR | DeBERTa (25 epochs) | DeBERTa + auxiliary | Auxiliary − DeBERTa (macro-F1) [95%] |
|---|---|---|---|---|---|
| all test labels | 21,900 | 0.605 / 0.598 | 0.620 / 0.604 | 0.645 / 0.623 | +0.025 [+0.023, +0.026] |
| all, without back-filled | 20,071 | 0.599 / 0.590 | 0.617 / 0.600 | 0.640 / 0.619 | +0.024 [+0.022, +0.026] |
| non-derived | 16,749 | 0.547 / 0.504 | 0.564 / 0.513 | 0.590 / 0.537 | +0.026 [+0.024, +0.028] |
| non-derived, without back-filled | 14,928 | 0.536 / 0.483 | 0.557 / 0.496 | 0.583 / 0.521 | +0.025 [+0.023, +0.027] |
| VulnCheck | 6,388 | 0.535 / 0.563 | 0.551 / 0.562 | 0.577 / 0.586 | +0.025 [+0.021, +0.029] |
| VulnCheck, without back-filled | 4,641 | 0.512 / 0.515 | 0.541 / 0.527 | 0.565 / 0.551 | +0.024 [+0.020, +0.029] |
| VulnCheck, back-filled only | 1,747 | 0.571 / 0.691 | 0.539 / 0.654 | 0.567 / 0.679 | +0.028 [+0.021, +0.033] |
