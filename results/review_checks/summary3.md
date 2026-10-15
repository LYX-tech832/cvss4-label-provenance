# Robustness checks (third set, generated automatically)

## (a) Share of VulnCheck (temporal split test set)

- independent test labels 7,242, of which VulnCheck 6,388 (88.2%); 
- non-derived test labels 16,749, of which VulnCheck 6,388 (38.1%).

## (b) Per-metric accuracy: all / non-derived / derived (TF-IDF; DeBERTa+auxiliary averaged over 5 seeds)

| Metric | TF-IDF all | non-derived | derived | Difference (all − non-derived) | DeBERTa+auxiliary all | non-derived | derived | Difference |
|---|---|---|---|---|---|---|---|---|
| AV | 0.901 | 0.876 | 0.980 | +0.025 | 0.902 | 0.872 | 0.998 | +0.030 |
| AC | 0.937 | 0.917 | 0.999 | +0.019 | 0.921 | 0.897 | 1.000 | +0.024 |
| AT | 0.847 | 0.800 | 0.999 | +0.047 | 0.813 | 0.756 | 0.999 | +0.057 |
| PR | 0.714 | 0.744 | 0.617 | -0.030 | 0.733 | 0.765 | 0.628 | -0.032 |
| UI | 0.862 | 0.828 | 0.970 | +0.033 | 0.845 | 0.808 | 0.964 | +0.036 |
| VC | 0.712 | 0.664 | 0.867 | +0.048 | 0.741 | 0.702 | 0.867 | +0.039 |
| VI | 0.707 | 0.663 | 0.850 | +0.044 | 0.728 | 0.689 | 0.856 | +0.039 |
| VA | 0.762 | 0.734 | 0.854 | +0.028 | 0.765 | 0.735 | 0.862 | +0.030 |
| SC | 0.850 | 0.813 | 0.971 | +0.037 | 0.778 | 0.718 | 0.971 | +0.059 |
| SI | 0.865 | 0.832 | 0.971 | +0.033 | 0.797 | 0.743 | 0.971 | +0.054 |
| SA | 0.911 | 0.893 | 0.971 | +0.018 | 0.840 | 0.799 | 0.971 | +0.040 |

## (c) VulnCheck also treated as a derived source

| Method | Scope | n | Mean macro-F1 | Band accuracy |
|---|---|---|---|---|
| TF-IDF | all | 21,900 | 0.605 | 0.598 |
| DeBERTa+auxiliary | all | 21,900 | 0.645 | 0.623 |
| TF-IDF | non-derived (as in the paper) | 16,749 | 0.547 | 0.504 |
| DeBERTa+auxiliary | non-derived (as in the paper) | 16,749 | 0.590 | 0.537 |
| TF-IDF | non-derived without VulnCheck | 10,361 | 0.533 | 0.468 |
| DeBERTa+auxiliary | non-derived without VulnCheck | 10,361 | 0.583 | 0.507 |

LLM sample (2,000 CVEs, paired bootstrap within label types, 1,000 resamples): mean macro-F1 difference DeepSeek − TF-IDF

| Scope | n | Of which VulnCheck | Difference [95%] |
|---|---|---|---|
| non-derived (as in the paper) | 1,700 | 619 | +0.021 [+0.006, +0.037] |
| non-derived without VulnCheck | 1,081 | 0 | +0.036 [+0.017, +0.056] |
| independent without VulnCheck | 81 | 0 | +0.051 [-0.026, +0.127] |
| VulnCheck within independent | 619 | 619 | +0.013 [-0.018, +0.036] |

## (d) Value distributions (all data)

| Source | n | AT:N | SC:N | SI:N | SA:N | UI:N | UI:P | UI:A | v4 value P / A when v3.1 has UI:R |
|---|---|---|---|---|---|---|---|---|---|
| VulDB | 12,882 | 100.0% | 98.8% | 98.8% | 98.8% | 88.1% | 11.9% | 0.0% | 77.4% / 0.0% (n=1,978) |
| independent, all | 10,154 | 86.7% | 80.8% | 82.3% | 91.1% | 75.3% | 14.4% | 10.3% | 59.8% / 38.3% (n=1,808) |
| independent without VulnCheck | 2,725 | 79.7% | 85.4% | 85.5% | 82.0% | 77.1% | 11.0% | 11.9% | 46.9% / 51.6% (n=548) |
| VulnCheck | 7,429 | 89.2% | 79.1% | 81.2% | 94.4% | 74.6% | 15.7% | 9.7% | 65.4% / 32.5% (n=1,260) |
| v4-only | 6,800 | 78.9% | 74.0% | 75.2% | 87.9% | 73.3% | 15.3% | 11.4% | — |
| other | 8,161 | 72.8% | 71.1% | 73.3% | 79.7% | 74.6% | 13.9% | 11.5% | 53.0% / 44.9% (n=430) |
