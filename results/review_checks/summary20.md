# Auxiliary-task model (5 epochs) − baseline encoder (25 epochs, selected for Table 2), by subset (generated automatically)

Seeds: auxiliary 5, baseline 5. Paired bootstrap, test CVEs resampled 1,000 times.

| Subset | n | Mean macro-F1 difference | Band accuracy difference |
|---|---|---|---|
| all | 21,900 | +0.025 [+0.023, +0.026] | +0.019 [+0.016, +0.022] |
| non-derived | 16,749 | +0.026 [+0.024, +0.028] | +0.024 [+0.020, +0.028] |
| R-inconsistent | 2,602 | +0.023 [+0.018, +0.027] | +0.024 [+0.015, +0.033] |
| no same-source v3.1 | 8,823 | +0.027 [+0.024, +0.029] | +0.021 [+0.015, +0.026] |
