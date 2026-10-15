# Robustness checks (second set, generated automatically)


## A. Auxiliary-task gain: unrounded differences and intervals including training randomness (mean macro-F1)

| Split | Scope | Difference (unrounded) | Difference per seed | Seed t interval (paired, df=4) | Two-level bootstrap interval (CVE × seed) |
|---|---|---|---|---|---|
| temporal | all | +0.0394 | +0.038, +0.042, +0.035, +0.039, +0.044 | [+0.035, +0.044] | [+0.036, +0.043] |
| temporal | non-derived | +0.0558 | +0.054, +0.057, +0.043, +0.062, +0.063 | [+0.046, +0.066] | [+0.050, +0.061] |
| loso-VulnCheck | all | +0.0264 | +0.023, +0.031, +0.029, +0.028, +0.021 | [+0.021, +0.032] | [+0.021, +0.032] |
| loso-GitHub_M | all | +0.0168 | +0.011, +0.014, +0.013, +0.028, +0.017 | [+0.008, +0.025] | [+0.009, +0.025] |
| loso-VulDB | all | +0.0207 | -0.002, +0.014, +0.027, +0.061, +0.004 | [-0.010, +0.052] | [+0.006, +0.038] |

## B. LLM comparison weighted by the true composition of the test set (each bootstrap draws 2,000 CVEs from the label types in their true proportions, 1,000 times; mean and 95% interval)

Composition of the test set: independent 7,242 (33.1%), other 5,243 (23.9%), derived 5,151 (23.5%), v4_only 4,264 (19.5%)

| Scope | Method | Mean macro-F1 | Band accuracy | Macro-F1 difference from TF-IDF | Band accuracy difference |
|---|---|---|---|---|---|
| weighted, all | DeepSeek (as in AutoCVSS) | 0.542 | 0.395 | -0.052 [-0.068, -0.035] | -0.195 [-0.224, -0.168] |
| weighted, all | DeepSeek (DONT_KNOW → most frequent) | 0.577 | 0.475 | -0.017 [-0.034, -0.002] | -0.115 [-0.144, -0.087] |
| weighted, all | TF-IDF | 0.594 | 0.590 | — | — |
| weighted, all | DeBERTa + auxiliary | 0.641 | 0.616 | +0.048 [+0.036, +0.060] | +0.027 [+0.009, +0.046] |
| weighted, non-derived | DeepSeek (as in AutoCVSS) | 0.558 | 0.461 | +0.019 [+0.004, +0.034] | -0.039 [-0.067, -0.011] |
| weighted, non-derived | DeepSeek (DONT_KNOW → most frequent) | 0.564 | 0.475 | +0.025 [+0.011, +0.040] | -0.025 [-0.053, +0.005] |
| weighted, non-derived | TF-IDF | 0.538 | 0.500 | — | — |
| weighted, non-derived | DeBERTa + auxiliary | 0.587 | 0.528 | +0.048 [+0.037, +0.060] | +0.028 [+0.006, +0.048] |

## C. Per-metric macro-F1 (temporal split test set; DeBERTa averaged over 5 seeds)

| Metric | Majority all / non-derived | TF-IDF all / non-derived / R-inconsistent | DeBERTa all / non-derived | DeBERTa+auxiliary all / non-derived / R-inconsistent | TF-IDF inflation (all − non-derived) | DeBERTa+auxiliary inflation |
|---|---|---|---|---|---|---|
| AV | 0.224 / 0.220 | 0.624 / 0.592 / 0.464 | 0.582 / 0.543 | 0.722 / 0.689 / 0.595 | +0.032 | +0.033 |
| AC | 0.479 / 0.478 | 0.660 / 0.529 / 0.553 | 0.661 / 0.582 | 0.681 / 0.594 / 0.606 | +0.131 | +0.087 |
| AT | 0.458 / 0.444 | 0.529 / 0.514 / 0.456 | 0.641 / 0.613 | 0.649 / 0.628 / 0.627 | +0.015 | +0.021 |
| PR | 0.228 / 0.239 | 0.609 / 0.629 / 0.615 | 0.545 / 0.537 | 0.664 / 0.689 / 0.639 | -0.020 | -0.025 |
| UI | 0.294 / 0.289 | 0.628 / 0.592 / 0.624 | 0.587 / 0.537 | 0.630 / 0.592 / 0.618 | +0.036 | +0.038 |
| VC | 0.141 / 0.093 | 0.701 / 0.573 / 0.552 | 0.695 / 0.535 | 0.731 / 0.602 / 0.553 | +0.128 | +0.129 |
| VI | 0.156 / 0.107 | 0.703 / 0.580 / 0.597 | 0.683 / 0.498 | 0.721 / 0.596 / 0.589 | +0.123 | +0.125 |
| VA | 0.127 / 0.066 | 0.752 / 0.552 / 0.535 | 0.745 / 0.538 | 0.756 / 0.580 / 0.576 | +0.199 | +0.176 |
| SC | 0.302 / 0.293 | 0.526 / 0.523 / 0.587 | 0.546 / 0.533 | 0.551 / 0.540 / 0.596 | +0.003 | +0.011 |
| SI | 0.304 / 0.296 | 0.531 / 0.530 / 0.588 | 0.553 / 0.542 | 0.563 / 0.554 / 0.604 | +0.002 | +0.009 |
| SA | 0.318 / 0.315 | 0.398 / 0.400 / 0.472 | 0.421 / 0.413 | 0.425 / 0.421 / 0.467 | -0.002 | +0.004 |

## D. Near-duplicates (maximum cosine similarity of TF-IDF term vectors; ≥ 0.9 counts as a near-duplicate)

| Label type | n | Near-duplicate of a v4 training description | Near-duplicate in the v3.1 pool | Median similarity (v4 training) |
|---|---|---|---|---|
| derived | 5,151 | 0.1% | 0.0% | 0.51 |
| independent | 7,242 | 0.7% | 0.0% | 0.25 |
| v4_only | 4,264 | 0.6% | 0.0% | 0.24 |
| other | 5,243 | 0.5% | 0.4% | 0.27 |

Without the test CVEs that are near-duplicates of v4 training descriptions (band accuracy; DeBERTa+auxiliary averaged over 5 seeds):
- derived, all (n = 5,151): TF-IDF 0.904, DeBERTa+auxiliary 0.903
- derived, without near-duplicates (n = 5,148): TF-IDF 0.904, DeBERTa+auxiliary 0.903
- non-derived, all (n = 16,749): TF-IDF 0.504, DeBERTa+auxiliary 0.537
- non-derived, without near-duplicates (n = 16,645): TF-IDF 0.502, DeBERTa+auxiliary 0.536

VulDB descriptions containing "classified/rated as <severity>": 37.2% (4,792 / 12,882); cross-table of the wordings and the v4.0 severity bands (all of VulDB's v4 labels):

| Wording | Critical | High | Low | Medium |
|---|---|---|---|---|
| critical | 22 | 470 | 14 | 2,928 |
| problematic | 0 | 14 | 75 | 1,267 |
| very critical | 2 | 0 | 0 | 0 |
| — | 279 | 930 | 234 | 6,647 |

Share of descriptions of other sources with the same wording: 0.00%

## E. Update time of the CNA container (providerMetadata.dateUpdated; any change of the CNA to its container updates it, so it is still an upper bound)

- Without an update time of the CNA container: 0; 
- of the 16,097 v4 samples published before 2026, 1,534 have a CNA container updated after the start of 2026 (9.5%); 
- of the 10,396 dual-scored ones, 701 (6.7%); 
- by source (at least 500 v4 samples in the training part): VulnCheck 69.3% (1,041); siemens 7.1% (523); VulDB 5.8% (7,731); GitHub_M 2.7% (1,529)

Typing repeated without these CVEs (before 2026, sources with at least 100 dual-scored CVEs):
- VulDB: 7,284 pairs, FD_oos 92.0% → derived (original type derived, original FD_oos 93.0%)
- siemens: 486 pairs, FD_oos 80.8% → independent (original type independent, original FD_oos 77.1%)
- intel: 424 pairs, FD_oos 47.7% → independent (original type independent, original FD_oos 47.7%)
- icscert: 386 pairs, FD_oos 61.2% → independent (original type independent, original FD_oos 66.1%)
- juniper: 199 pairs, FD_oos 51.7% → independent (original type independent, original FD_oos 51.7%)
- twcert: 117 pairs, FD_oos 83.3% → independent (original type independent, original FD_oos 83.3%)
- ABB: 105 pairs, FD_oos 37.5% → independent (original type independent, original FD_oos 37.5%)

TF-IDF baseline retrained without these training samples (same test set):
- original training set (training 16,097), all: mean macro-F1 0.605, band accuracy 0.598, underestimation rate 0.136
- original training set (training 16,097), non-derived: mean macro-F1 0.547, band accuracy 0.504, underestimation rate 0.155
- without CNA containers updated after the start of 2026 (training 14,563), all: mean macro-F1 0.603, band accuracy 0.589, underestimation rate 0.144
- without CNA containers updated after the start of 2026 (training 14,563), non-derived: mean macro-F1 0.541, band accuracy 0.492, underestimation rate 0.165

## F. Synthetic conversion convention (data before 2026; each source's v4 labels replaced by a deterministic conversion other than rule R, then tested)

| CNA | Pairs | Rule-R agreement | FD_oos (rule-R fallback) | FD_oos (seen only) | Fallback rate | Typed as derived |
|---|---|---|---|---|---|---|
| VulDB | 7,731 | 78.9% | 99.7% | 100.0% | 0.6% | yes |
| siemens | 523 | 55.3% | 78.3% | 100.0% | 35.0% | no |
| intel | 424 | 17.0% | 77.3% | 100.0% | 32.0% | no |
| icscert | 401 | 62.1% | 80.2% | 100.0% | 38.8% | no |
| VulnCheck | 236 | 72.9% | 98.6% | 100.0% | 1.4% | yes |
| juniper | 199 | 65.3% | 53.3% | 100.0% | 61.7% | no |
| twcert | 117 | 86.3% | 86.1% | 100.0% | 22.2% | no |
| ABB | 105 | 48.6% | 50.0% | 100.0% | 68.8% | no |
