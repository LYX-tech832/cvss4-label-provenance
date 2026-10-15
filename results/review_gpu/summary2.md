# Shuffled-label control and ten-epoch LOSO baselines (GPU runs; generated automatically)

## 1. Negative control with shuffled v3.1 labels (temporal split)


### all: n = 21,900

| Variant | Seeds | Mean macro-F1 (mean ± sd) | Macro-F1 of the 7 shared metrics | Macro-F1 of AT/SC/SI/SA | Band accuracy |
|---|---|---|---|---|---|
| baseline 5 epochs | 5 | 0.605 ± 0.002 | 0.643 | 0.540 | 0.569 |
| baseline 10 epochs | 3 | 0.617 ± 0.001 | 0.662 | 0.539 | 0.592 |
| shuffled v3.1 auxiliary 5 epochs | 3 | 0.628 ± 0.005 | 0.674 | 0.548 | 0.599 |
| v3.1 auxiliary 5 epochs | 5 | 0.645 ± 0.002 | 0.701 | 0.547 | 0.623 |
| v3.1 auxiliary 10 epochs | 3 | 0.645 ± 0.004 | 0.701 | 0.545 | 0.631 |
| CWE auxiliary 5 epochs | 3 | 0.618 ± 0.003 | 0.662 | 0.540 | 0.587 |
| pseudo-labels 5 epochs | 3 | 0.643 ± 0.003 | 0.697 | 0.549 | 0.635 |

Paired bootstrap (A − B; mean macro-F1 / band accuracy; 95% interval):

| A − B | Common seeds | Mean macro-F1 difference | Band accuracy difference |
|---|---|---|---|
| v3.1 auxiliary 5 epochs − shuffled v3.1 auxiliary 5 epochs | 3 | +0.016 [+0.014, +0.018] | +0.025 [+0.021, +0.028] |
| shuffled v3.1 auxiliary 5 epochs − baseline 5 epochs | 3 | +0.022 [+0.020, +0.024] | +0.031 [+0.027, +0.035] |
| shuffled v3.1 auxiliary 5 epochs − baseline 10 epochs | 3 | +0.011 [+0.009, +0.013] | +0.007 [+0.004, +0.011] |
| v3.1 auxiliary 5 epochs − baseline 5 epochs | 5 | +0.039 [+0.037, +0.041] | +0.054 [+0.050, +0.058] |
| shuffled v3.1 auxiliary 5 epochs − CWE auxiliary 5 epochs | 3 | +0.010 [+0.008, +0.013] | +0.012 [+0.008, +0.016] |
| v3.1 auxiliary 5 epochs − CWE auxiliary 5 epochs | 3 | +0.026 [+0.024, +0.028] | +0.036 [+0.032, +0.041] |

### non-derived: n = 16,749

| Variant | Seeds | Mean macro-F1 (mean ± sd) | Macro-F1 of the 7 shared metrics | Macro-F1 of AT/SC/SI/SA | Band accuracy |
|---|---|---|---|---|---|
| baseline 5 epochs | 5 | 0.534 ± 0.004 | 0.539 | 0.525 | 0.468 |
| baseline 10 epochs | 3 | 0.553 ± 0.005 | 0.569 | 0.525 | 0.496 |
| shuffled v3.1 auxiliary 5 epochs | 3 | 0.567 ± 0.007 | 0.584 | 0.537 | 0.506 |
| v3.1 auxiliary 5 epochs | 5 | 0.590 ± 0.005 | 0.620 | 0.536 | 0.537 |
| v3.1 auxiliary 10 epochs | 3 | 0.590 ± 0.007 | 0.623 | 0.534 | 0.547 |
| CWE auxiliary 5 epochs | 3 | 0.556 ± 0.005 | 0.572 | 0.527 | 0.493 |
| pseudo-labels 5 epochs | 3 | 0.594 ± 0.000 | 0.624 | 0.541 | 0.552 |

Paired bootstrap (A − B; mean macro-F1 / band accuracy; 95% interval):

| A − B | Common seeds | Mean macro-F1 difference | Band accuracy difference |
|---|---|---|---|
| v3.1 auxiliary 5 epochs − shuffled v3.1 auxiliary 5 epochs | 3 | +0.021 [+0.019, +0.023] | +0.032 [+0.027, +0.036] |
| shuffled v3.1 auxiliary 5 epochs − baseline 5 epochs | 3 | +0.031 [+0.028, +0.033] | +0.039 [+0.034, +0.044] |
| shuffled v3.1 auxiliary 5 epochs − baseline 10 epochs | 3 | +0.013 [+0.012, +0.015] | +0.010 [+0.005, +0.015] |
| v3.1 auxiliary 5 epochs − baseline 5 epochs | 5 | +0.056 [+0.054, +0.058] | +0.069 [+0.065, +0.074] |
| shuffled v3.1 auxiliary 5 epochs − CWE auxiliary 5 epochs | 3 | +0.011 [+0.009, +0.014] | +0.013 [+0.008, +0.018] |
| v3.1 auxiliary 5 epochs − CWE auxiliary 5 epochs | 3 | +0.032 [+0.029, +0.034] | +0.045 [+0.039, +0.050] |

### R-inconsistent: n = 2,602

| Variant | Seeds | Mean macro-F1 (mean ± sd) | Macro-F1 of the 7 shared metrics | Macro-F1 of AT/SC/SI/SA | Band accuracy |
|---|---|---|---|---|---|
| baseline 5 epochs | 5 | 0.550 ± 0.007 | 0.536 | 0.573 | 0.496 |
| baseline 10 epochs | 3 | 0.556 ± 0.004 | 0.551 | 0.566 | 0.519 |
| shuffled v3.1 auxiliary 5 epochs | 3 | 0.569 ± 0.010 | 0.568 | 0.572 | 0.528 |
| v3.1 auxiliary 5 epochs | 5 | 0.588 ± 0.008 | 0.597 | 0.573 | 0.549 |
| v3.1 auxiliary 10 epochs | 3 | 0.588 ± 0.007 | 0.603 | 0.562 | 0.550 |
| CWE auxiliary 5 epochs | 3 | 0.557 ± 0.008 | 0.555 | 0.560 | 0.525 |
| pseudo-labels 5 epochs | 3 | 0.579 ± 0.005 | 0.589 | 0.562 | 0.557 |

Paired bootstrap (A − B; mean macro-F1 / band accuracy; 95% interval):

| A − B | Common seeds | Mean macro-F1 difference | Band accuracy difference |
|---|---|---|---|
| v3.1 auxiliary 5 epochs − shuffled v3.1 auxiliary 5 epochs | 3 | +0.014 [+0.009, +0.019] | +0.016 [+0.006, +0.027] |
| shuffled v3.1 auxiliary 5 epochs − baseline 5 epochs | 3 | +0.019 [+0.014, +0.026] | +0.037 [+0.025, +0.049] |
| shuffled v3.1 auxiliary 5 epochs − baseline 10 epochs | 3 | +0.013 [+0.009, +0.018] | +0.009 [-0.003, +0.020] |
| v3.1 auxiliary 5 epochs − baseline 5 epochs | 5 | +0.039 [+0.032, +0.045] | +0.053 [+0.042, +0.064] |
| shuffled v3.1 auxiliary 5 epochs − CWE auxiliary 5 epochs | 3 | +0.013 [+0.007, +0.019] | +0.003 [-0.010, +0.016] |
| v3.1 auxiliary 5 epochs − CWE auxiliary 5 epochs | 3 | +0.027 [+0.021, +0.033] | +0.019 [+0.006, +0.033] |

### no same-source v3.1: n = 8,823

| Variant | Seeds | Mean macro-F1 (mean ± sd) | Macro-F1 of the 7 shared metrics | Macro-F1 of AT/SC/SI/SA | Band accuracy |
|---|---|---|---|---|---|
| baseline 5 epochs | 5 | 0.515 ± 0.006 | 0.528 | 0.493 | 0.426 |
| baseline 10 epochs | 3 | 0.537 ± 0.005 | 0.560 | 0.496 | 0.445 |
| shuffled v3.1 auxiliary 5 epochs | 3 | 0.552 ± 0.007 | 0.575 | 0.511 | 0.457 |
| v3.1 auxiliary 5 epochs | 5 | 0.575 ± 0.004 | 0.612 | 0.511 | 0.491 |
| v3.1 auxiliary 10 epochs | 3 | 0.574 ± 0.007 | 0.611 | 0.508 | 0.495 |
| CWE auxiliary 5 epochs | 3 | 0.543 ± 0.006 | 0.566 | 0.504 | 0.461 |
| pseudo-labels 5 epochs | 3 | 0.576 ± 0.002 | 0.614 | 0.510 | 0.500 |

Paired bootstrap (A − B; mean macro-F1 / band accuracy; 95% interval):

| A − B | Common seeds | Mean macro-F1 difference | Band accuracy difference |
|---|---|---|---|
| v3.1 auxiliary 5 epochs − shuffled v3.1 auxiliary 5 epochs | 3 | +0.023 [+0.020, +0.026] | +0.036 [+0.030, +0.043] |
| shuffled v3.1 auxiliary 5 epochs − baseline 5 epochs | 3 | +0.034 [+0.031, +0.037] | +0.030 [+0.023, +0.036] |
| shuffled v3.1 auxiliary 5 epochs − baseline 10 epochs | 3 | +0.015 [+0.013, +0.018] | +0.012 [+0.005, +0.018] |
| v3.1 auxiliary 5 epochs − baseline 5 epochs | 5 | +0.060 [+0.057, +0.063] | +0.066 [+0.058, +0.072] |
| shuffled v3.1 auxiliary 5 epochs − CWE auxiliary 5 epochs | 3 | +0.009 [+0.006, +0.012] | -0.003 [-0.010, +0.004] |
| v3.1 auxiliary 5 epochs − CWE auxiliary 5 epochs | 3 | +0.032 [+0.028, +0.035] | +0.033 [+0.026, +0.040] |

### AT: the 1,034 labels of the R-inconsistent subset with AT:Present

| Variant | Seeds | Share predicted as AT:None | Share predicted as AT:Present on the whole test set |
|---|---|---|---|
| baseline 5 epochs | 5 | 0.545 | 0.226 |
| baseline 10 epochs | 3 | 0.525 | 0.230 |
| shuffled v3.1 auxiliary 5 epochs | 3 | 0.631 | 0.177 |
| v3.1 auxiliary 5 epochs | 5 | 0.627 | 0.162 |
| v3.1 auxiliary 10 epochs | 3 | 0.656 | 0.171 |
| CWE auxiliary 5 epochs | 3 | 0.637 | 0.174 |
| pseudo-labels 5 epochs | 3 | 0.860 | 0.075 |

(Share of AT:Present among the true labels of the whole test set: 0.155)


## 2. LOSO splits: baseline trained for 10 epochs


### Held out VulnCheck: n = 7,429

| Variant | Seeds | Mean macro-F1 (mean ± sd) | Band accuracy | Underestimation |
|---|---|---|---|---|
| baseline 5 epochs | 5 | 0.581 ± 0.003 | 0.579 | 0.131 |
| baseline 10 epochs | 5 | 0.586 ± 0.005 | 0.593 | 0.141 |
| v3.1 auxiliary 5 epochs | 5 | 0.607 ± 0.004 | 0.601 | 0.125 |

| A − B | Common seeds | Mean macro-F1 difference | Band accuracy difference |
|---|---|---|---|
| baseline 10 epochs − baseline 5 epochs | 5 | +0.005 [+0.003, +0.008] | +0.013 [+0.008, +0.019] |
| v3.1 auxiliary 5 epochs − baseline 10 epochs | 5 | +0.021 [+0.018, +0.024] | +0.008 [+0.002, +0.014] |
| v3.1 auxiliary 5 epochs − baseline 5 epochs | 5 | +0.026 [+0.023, +0.029] | +0.022 [+0.015, +0.027] |

### Held out GitHub_M: n = 5,129

| Variant | Seeds | Mean macro-F1 (mean ± sd) | Band accuracy | Underestimation |
|---|---|---|---|---|
| baseline 5 epochs | 5 | 0.525 ± 0.007 | 0.462 | 0.198 |
| baseline 10 epochs | 5 | 0.523 ± 0.004 | 0.472 | 0.234 |
| v3.1 auxiliary 5 epochs | 5 | 0.542 ± 0.004 | 0.493 | 0.191 |

| A − B | Common seeds | Mean macro-F1 difference | Band accuracy difference |
|---|---|---|---|
| baseline 10 epochs − baseline 5 epochs | 5 | -0.003 [-0.006, +0.001] | +0.010 [+0.003, +0.017] |
| v3.1 auxiliary 5 epochs − baseline 10 epochs | 5 | +0.019 [+0.016, +0.023] | +0.021 [+0.014, +0.029] |
| v3.1 auxiliary 5 epochs − baseline 5 epochs | 5 | +0.017 [+0.013, +0.020] | +0.031 [+0.024, +0.038] |

### Held out VulDB: n = 12,882

| Variant | Seeds | Mean macro-F1 (mean ± sd) | Band accuracy | Underestimation |
|---|---|---|---|---|
| baseline 5 epochs | 5 | 0.382 ± 0.016 | 0.266 | 0.021 |
| baseline 10 epochs | 5 | 0.370 ± 0.021 | 0.274 | 0.026 |
| v3.1 auxiliary 5 epochs | 5 | 0.402 ± 0.014 | 0.257 | 0.024 |

| A − B | Common seeds | Mean macro-F1 difference | Band accuracy difference |
|---|---|---|---|
| baseline 10 epochs − baseline 5 epochs | 5 | -0.012 [-0.014, -0.010] | +0.008 [+0.005, +0.011] |
| v3.1 auxiliary 5 epochs − baseline 10 epochs | 5 | +0.032 [+0.030, +0.034] | -0.017 [-0.020, -0.014] |
| v3.1 auxiliary 5 epochs − baseline 5 epochs | 5 | +0.021 [+0.019, +0.023] | -0.009 [-0.012, -0.005] |

## 3. Shuffled-label control with 5% of the v4 training labels (temporal split)


### all: n = 21,900

| Variant | Seeds | Mean macro-F1 (mean ± sd) | Band accuracy |
|---|---|---|---|
| 5% + v3.1 auxiliary | 3 | 0.618 ± 0.004 | 0.609 |
| 5% + shuffled v3.1 auxiliary | 3 | 0.498 ± 0.006 | 0.445 |
| all labels, baseline 5 epochs | 5 | 0.605 ± 0.002 | 0.569 |
| all labels, baseline 10 epochs | 3 | 0.617 ± 0.001 | 0.592 |

| A − B | Common seeds | Mean macro-F1 difference | Band accuracy difference |
|---|---|---|---|
| 5% + v3.1 auxiliary − 5% + shuffled v3.1 auxiliary | 3 | +0.120 [+0.117, +0.123] | +0.164 [+0.159, +0.169] |
| 5% + shuffled v3.1 auxiliary − all labels, baseline 5 epochs | 3 | -0.108 [-0.111, -0.105] | -0.123 [-0.128, -0.118] |
| 5% + shuffled v3.1 auxiliary − all labels, baseline 10 epochs | 3 | -0.120 [-0.122, -0.117] | -0.147 [-0.152, -0.142] |
| 5% + v3.1 auxiliary − all labels, baseline 10 epochs | 3 | +0.001 [-0.002, +0.004] | +0.017 [+0.012, +0.022] |

### non-derived: n = 16,749

| Variant | Seeds | Mean macro-F1 (mean ± sd) | Band accuracy |
|---|---|---|---|
| 5% + v3.1 auxiliary | 3 | 0.562 ± 0.008 | 0.526 |
| 5% + shuffled v3.1 auxiliary | 3 | 0.413 ± 0.004 | 0.313 |
| all labels, baseline 5 epochs | 5 | 0.534 ± 0.004 | 0.468 |
| all labels, baseline 10 epochs | 3 | 0.553 ± 0.005 | 0.496 |

| A − B | Common seeds | Mean macro-F1 difference | Band accuracy difference |
|---|---|---|---|
| 5% + v3.1 auxiliary − 5% + shuffled v3.1 auxiliary | 3 | +0.149 [+0.145, +0.152] | +0.213 [+0.207, +0.219] |
| 5% + shuffled v3.1 auxiliary − all labels, baseline 5 epochs | 3 | -0.123 [-0.126, -0.120] | -0.153 [-0.160, -0.147] |
| 5% + shuffled v3.1 auxiliary − all labels, baseline 10 epochs | 3 | -0.140 [-0.144, -0.137] | -0.183 [-0.189, -0.176] |
| 5% + v3.1 auxiliary − all labels, baseline 10 epochs | 3 | +0.009 [+0.006, +0.012] | +0.030 [+0.024, +0.036] |

### R-inconsistent: n = 2,602

| Variant | Seeds | Mean macro-F1 (mean ± sd) | Band accuracy |
|---|---|---|---|
| 5% + v3.1 auxiliary | 3 | 0.550 ± 0.003 | 0.520 |
| 5% + shuffled v3.1 auxiliary | 3 | 0.431 ± 0.005 | 0.371 |
| all labels, baseline 5 epochs | 5 | 0.550 ± 0.007 | 0.496 |
| all labels, baseline 10 epochs | 3 | 0.556 ± 0.004 | 0.519 |

| A − B | Common seeds | Mean macro-F1 difference | Band accuracy difference |
|---|---|---|---|
| 5% + v3.1 auxiliary − 5% + shuffled v3.1 auxiliary | 3 | +0.120 [+0.109, +0.129] | +0.150 [+0.133, +0.166] |
| 5% + shuffled v3.1 auxiliary − all labels, baseline 5 epochs | 3 | -0.120 [-0.127, -0.111] | -0.120 [-0.136, -0.105] |
| 5% + shuffled v3.1 auxiliary − all labels, baseline 10 epochs | 3 | -0.125 [-0.134, -0.117] | -0.148 [-0.164, -0.133] |
| 5% + v3.1 auxiliary − all labels, baseline 10 epochs | 3 | -0.006 [-0.014, +0.001] | +0.002 [-0.013, +0.017] |

### AT: share of the 1,034 labels of the R-inconsistent subset with AT:Present that are predicted as None

| Variant | Share |
|---|---|
| 5% + v3.1 auxiliary | 0.848 |
| 5% + shuffled v3.1 auxiliary | 0.968 |
| all labels, baseline 5 epochs | 0.545 |
| all labels, baseline 10 epochs | 0.525 |
