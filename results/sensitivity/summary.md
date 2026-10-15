# Sensitivity analyses (generated automatically)

## (a) Threshold of the source typing

Out-of-sample functional dependence FD_oos of each source (all data before 2026 / 2025 data only; sources with at least 100 pairs):

| Source | FD_oos (before 2026) | FD_oos (2025) |
|---|---|---|
| VulDB | 93.0% | 99.9% |
| twcert | 83.3% | 83.3% |
| siemens | 77.1% | 78.0% |
| icscert | 66.1% | 60.7% |
| juniper | 51.7% | — |
| intel | 47.7% | 48.8% |
| VulnCheck | 40.8% | 40.8% |
| ABB | 37.5% | — |

Sources typed as derived under each typing: threshold 0.80: VulDB, twcert; threshold 0.90 (main setting): VulDB; threshold 0.95: none; recent window (2025 data, threshold 0.95): VulDB

### Evaluation inflation: all test labels vs without derived

| Typing / setting / scope | Mean macro-F1 (full label set) | Mean macro-F1 (sklearn default) | Exact vector | Band accuracy | Underestimation |
|---|---|---|---|---|---|
| T2 TF-IDF+LR, all (n=21,900) | 0.605 | 0.605 | 0.237 | 0.598 | 0.136 |
| T1 rule R, all (n=13,077) | 0.865 | 0.865 | 0.801 | 0.951 | 0.009 |
| threshold 0.80, T2 TF-IDF+LR, without derived (n=16,609) | 0.546 | 0.546 | 0.167 | 0.502 | 0.156 |
| threshold 0.80, T1 rule R, without derived (n=7,786) | 0.835 | 0.835 | 0.669 | 0.918 | 0.015 |
| threshold 0.90 (main setting), T2 TF-IDF+LR, without derived (n=16,749) | 0.547 | 0.547 | 0.171 | 0.504 | 0.155 |
| threshold 0.90 (main setting), T1 rule R, without derived (n=7,926) | 0.835 | 0.835 | 0.672 | 0.919 | 0.015 |
| threshold 0.95: no source typed as derived, no distinction possible | | | | | |
| recent window (2025 data, threshold 0.95), T2 TF-IDF+LR, without derived (n=16,749) | 0.547 | 0.547 | 0.171 | 0.504 | 0.155 |
| recent window (2025 data, threshold 0.95), T1 rule R, without derived (n=7,926) | 0.835 | 0.835 | 0.672 | 0.919 | 0.015 |

### LLM comparison (the same 2,000 CVEs): derived and non-derived groups under each typing

Each cell: mean macro-F1 (full label set) / mean macro-F1 (sklearn default) / band accuracy

| Typing | Group | AutoCVSS + DeepSeek | TF-IDF+LR | TF-IDF+LR (description only) | DeBERTa+auxiliary (W4, 5 seeds) |
|---|---|---|---|---|---|
| threshold 0.80 | derived (n=311) | 0.483 / 0.503 / 0.183 | 0.645 / 0.662 / 0.887 | 0.643 / 0.660 / 0.897 | 0.667 / 0.688 / 0.904 |
| threshold 0.80 | non-derived (n=1689) | 0.557 / 0.557 / 0.460 | 0.535 / 0.535 / 0.493 | 0.527 / 0.527 / 0.491 | 0.585 / 0.585 / 0.524 |
| threshold 0.90 (main setting) | derived (n=300) | 0.445 / 0.466 / 0.180 | 0.578 / 0.623 / 0.883 | 0.575 / 0.620 / 0.893 | 0.603 / 0.652 / 0.904 |
| threshold 0.90 (main setting) | non-derived (n=1700) | 0.557 / 0.557 / 0.459 | 0.536 / 0.536 / 0.496 | 0.528 / 0.528 / 0.494 | 0.586 / 0.586 / 0.526 |
| threshold 0.95 | non-derived (n=2000) | 0.547 / 0.547 / 0.417 | 0.579 / 0.579 / 0.554 | 0.572 / 0.572 / 0.554 | 0.628 / 0.628 / 0.583 |
| recent window (2025 data, threshold 0.95) | derived (n=300) | 0.445 / 0.466 / 0.180 | 0.578 / 0.623 / 0.883 | 0.575 / 0.620 / 0.893 | 0.603 / 0.652 / 0.904 |
| recent window (2025 data, threshold 0.95) | non-derived (n=1700) | 0.557 / 0.557 / 0.459 | 0.536 / 0.536 / 0.496 | 0.528 / 0.528 / 0.494 | 0.586 / 0.586 / 0.526 |

## (b) Definition of the per-group macro-F1 (main typing, the same 2,000 CVEs)

| Label type | Definition | AutoCVSS + DeepSeek | TF-IDF+LR | TF-IDF+LR (description only) | DeBERTa+auxiliary (W4, 5 seeds) | Ranking (high → low) |
|---|---|---|---|---|---|---|
| derived (n=300) | full label set | 0.445 | 0.578 | 0.575 | 0.603 | DeBERTa+auxiliary (W4, 5 seeds) > TF-IDF+LR > TF-IDF+LR (description only) > AutoCVSS + DeepSeek |
| derived (n=300) | sklearn default | 0.466 | 0.623 | 0.620 | 0.652 | DeBERTa+auxiliary (W4, 5 seeds) > TF-IDF+LR > TF-IDF+LR (description only) > AutoCVSS + DeepSeek |
| independent (n=700) | full label set | 0.565 | 0.566 | 0.556 | 0.599 | DeBERTa+auxiliary (W4, 5 seeds) > TF-IDF+LR > AutoCVSS + DeepSeek > TF-IDF+LR (description only) |
| independent (n=700) | sklearn default | 0.565 | 0.566 | 0.556 | 0.599 | DeBERTa+auxiliary (W4, 5 seeds) > TF-IDF+LR > AutoCVSS + DeepSeek > TF-IDF+LR (description only) |
| v4_only (n=500) | full label set | 0.536 | 0.473 | 0.462 | 0.553 | DeBERTa+auxiliary (W4, 5 seeds) > AutoCVSS + DeepSeek > TF-IDF+LR > TF-IDF+LR (description only) |
| v4_only (n=500) | sklearn default | 0.536 | 0.473 | 0.462 | 0.553 | DeBERTa+auxiliary (W4, 5 seeds) > AutoCVSS + DeepSeek > TF-IDF+LR > TF-IDF+LR (description only) |
| other (n=500) | full label set | 0.556 | 0.532 | 0.526 | 0.575 | DeBERTa+auxiliary (W4, 5 seeds) > AutoCVSS + DeepSeek > TF-IDF+LR > TF-IDF+LR (description only) |
| other (n=500) | sklearn default | 0.556 | 0.532 | 0.526 | 0.575 | DeBERTa+auxiliary (W4, 5 seeds) > AutoCVSS + DeepSeek > TF-IDF+LR > TF-IDF+LR (description only) |
