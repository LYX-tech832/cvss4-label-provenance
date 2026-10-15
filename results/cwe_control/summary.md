# CWE auxiliary-task control (T2 temporal split, generated automatically)

The first three groups use only the description as input (no CWE identifier); the two W4 groups (description + CWE identifier) are references. Configuration: 5 epochs, inv_sqrt class weighting, λ = 0.5; seeds 0–2.


## Mean ± standard deviation of each group (all test labels)

| Group | Seeds | macro-F1 | v4-F1 | exact | MAE | band | under | H+C rec. |
|---|---|---|---|---|---|---|---|---|
| no auxiliary (description only) | 3 | 0.608 ± 0.003 | 0.556 ± 0.003 | 0.189 ± 0.010 | 1.425 ± 0.078 | 0.564 ± 0.015 | 0.148 ± 0.025 | 0.838 ± 0.022 |
| v3.1 auxiliary (description only) | 3 | 0.645 ± 0.002 | 0.564 ± 0.009 | 0.238 ± 0.005 | 1.171 ± 0.030 | 0.631 ± 0.007 | 0.147 ± 0.004 | 0.813 ± 0.005 |
| CWE auxiliary (description only) | 3 | 0.618 ± 0.003 | 0.553 ± 0.005 | 0.202 ± 0.007 | 1.303 ± 0.013 | 0.587 ± 0.006 | 0.149 ± 0.002 | 0.821 ± 0.008 |
| no auxiliary (W4, description + CWE) | 3 | 0.606 ± 0.003 | 0.551 ± 0.003 | 0.186 ± 0.009 | 1.440 ± 0.025 | 0.568 ± 0.003 | 0.163 ± 0.013 | 0.820 ± 0.018 |
| v3.1 auxiliary (W4, description + CWE) | 3 | 0.644 ± 0.001 | 0.561 ± 0.004 | 0.237 ± 0.004 | 1.169 ± 0.028 | 0.624 ± 0.003 | 0.137 ± 0.010 | 0.827 ± 0.007 |

## Mean ± standard deviation of each group (without derived)

| Group | Seeds | macro-F1 | v4-F1 | exact | MAE | band | under | H+C rec. |
|---|---|---|---|---|---|---|---|---|
| no auxiliary (description only) | 3 | 0.535 ± 0.005 | 0.535 ± 0.004 | 0.110 ± 0.010 | 1.646 ± 0.097 | 0.461 ± 0.019 | 0.172 ± 0.030 | 0.850 ± 0.022 |
| v3.1 auxiliary (description only) | 3 | 0.588 ± 0.004 | 0.547 ± 0.010 | 0.164 ± 0.006 | 1.322 ± 0.039 | 0.546 ± 0.010 | 0.170 ± 0.005 | 0.824 ± 0.005 |
| CWE auxiliary (description only) | 3 | 0.556 ± 0.005 | 0.534 ± 0.008 | 0.124 ± 0.005 | 1.476 ± 0.010 | 0.493 ± 0.007 | 0.171 ± 0.005 | 0.832 ± 0.008 |
| no auxiliary (W4, description + CWE) | 3 | 0.536 ± 0.003 | 0.529 ± 0.005 | 0.109 ± 0.010 | 1.657 ± 0.038 | 0.467 ± 0.005 | 0.189 ± 0.018 | 0.832 ± 0.020 |
| v3.1 auxiliary (W4, description + CWE) | 3 | 0.587 ± 0.005 | 0.544 ± 0.005 | 0.164 ± 0.003 | 1.315 ± 0.034 | 0.537 ± 0.003 | 0.157 ± 0.013 | 0.839 ± 0.007 |

## Paired bootstrap (A − B; averaged over seeds first; 1,000 resamples; 95% percentile intervals)

| A − B | Scope | n | Seeds (A/B) | Mean macro-F1 difference | Band accuracy difference | Underestimation difference | Score MAE difference |
|---|---|---|---|---|---|---|---|
| v31 − none | all test labels | 21,900 | 3/3 | +0.036 [+0.034, +0.039] | +0.067 [+0.063, +0.072] | -0.002 [-0.004, +0.001] | -0.254 [-0.269, -0.240] |
| v31 − none | without derived | 16,749 | 3/3 | +0.053 [+0.051, +0.055] | +0.085 [+0.080, +0.091] | -0.002 [-0.006, +0.002] | -0.324 [-0.342, -0.306] |
| CWE − none | all test labels | 21,900 | 3/3 | +0.009 [+0.007, +0.011] | +0.024 [+0.020, +0.028] | +0.000 [-0.003, +0.003] | -0.122 [-0.136, -0.107] |
| CWE − none | without derived | 16,749 | 3/3 | +0.021 [+0.018, +0.023] | +0.032 [+0.026, +0.037] | -0.001 [-0.005, +0.003] | -0.170 [-0.188, -0.151] |
| v31 − CWE | all test labels | 21,900 | 3/3 | +0.027 [+0.025, +0.029] | +0.043 [+0.039, +0.048] | -0.002 [-0.005, +0.001] | -0.132 [-0.146, -0.119] |
| v31 − CWE | without derived | 16,749 | 3/3 | +0.032 [+0.030, +0.035] | +0.054 [+0.048, +0.059] | -0.001 [-0.005, +0.003] | -0.154 [-0.171, -0.137] |
| v31(W4) − none(W4) | all test labels | 21,900 | 3/3 | +0.038 [+0.036, +0.040] | +0.055 [+0.051, +0.059] | -0.026 [-0.029, -0.023] | -0.272 [-0.288, -0.256] |
| v31(W4) − none(W4) | without derived | 16,749 | 3/3 | +0.051 [+0.049, +0.054] | +0.071 [+0.065, +0.076] | -0.031 [-0.035, -0.027] | -0.342 [-0.358, -0.322] |

Group names: none = no auxiliary task, v31 = v3.1 auxiliary task, CWE = CWE auxiliary task (all with the description only); (W4) = input with the CWE identifier. Lower underestimation rate and MAE are better, so a negative difference in these two columns is an improvement.

## Per-metric macro-F1 differences (all test labels; each group averaged over seeds first)

| Metric | v31 − none | CWE − none | v31 − CWE | v31(W4) − none(W4) | v31(W4) − none(W4), seeds 0–4 |
|---|---|---|---|---|---|
| AV | +0.119 | +0.032 | +0.087 | +0.144 | +0.140 |
| AC | +0.015 | +0.013 | +0.002 | +0.018 | +0.020 |
| AT | +0.011 | -0.002 | +0.013 | +0.001 | +0.008 |
| PR | +0.136 | +0.036 | +0.101 | +0.117 | +0.119 |
| UI | +0.034 | +0.011 | +0.023 | +0.043 | +0.043 |
| VC | +0.037 | +0.014 | +0.024 | +0.039 | +0.035 |
| VI | +0.037 | +0.019 | +0.019 | +0.038 | +0.038 |
| VA | +0.015 | +0.003 | +0.012 | +0.010 | +0.011 |
| SC | -0.003 | -0.009 | +0.006 | +0.001 | +0.005 |
| SI | -0.004 | -0.007 | +0.003 | +0.005 | +0.010 |
| SA | +0.002 | -0.005 | +0.008 | +0.002 | +0.004 |
| **mean of the 7 metrics with a v3.1 counterpart** | +0.056 | +0.018 | +0.038 | +0.058 | +0.058 |
| **mean of AT/SC/SI/SA** | +0.002 | -0.006 | +0.007 | +0.002 | +0.007 |
| **mean of the 11 metrics** | +0.036 | +0.009 | +0.027 | +0.038 | +0.039 |

## Per-metric macro-F1 differences (without derived; each group averaged over seeds first)

| Metric | v31 − none | CWE − none | v31 − CWE | v31(W4) − none(W4) | v31(W4) − none(W4), seeds 0–4 |
|---|---|---|---|---|---|
| AV | +0.126 | +0.032 | +0.093 | +0.148 | +0.146 |
| AC | +0.006 | +0.003 | +0.002 | +0.004 | +0.012 |
| AT | +0.017 | +0.003 | +0.013 | +0.009 | +0.014 |
| PR | +0.172 | +0.051 | +0.121 | +0.153 | +0.153 |
| UI | +0.040 | +0.011 | +0.028 | +0.050 | +0.054 |
| VC | +0.078 | +0.043 | +0.035 | +0.061 | +0.067 |
| VI | +0.094 | +0.060 | +0.033 | +0.095 | +0.098 |
| VA | +0.045 | +0.040 | +0.005 | +0.031 | +0.042 |
| SC | -0.000 | -0.008 | +0.008 | +0.003 | +0.007 |
| SI | -0.001 | -0.006 | +0.005 | +0.008 | +0.013 |
| SA | +0.006 | -0.004 | +0.010 | +0.004 | +0.007 |
| **mean of the 7 metrics with a v3.1 counterpart** | +0.080 | +0.035 | +0.045 | +0.077 | +0.082 |
| **mean of AT/SC/SI/SA** | +0.005 | -0.004 | +0.009 | +0.006 | +0.010 |
| **mean of the 11 metrics** | +0.053 | +0.021 | +0.032 | +0.051 | +0.056 |

## Best epoch of each run (selected by mean validation macro-F1; epochs counted from 0, 5 epochs)

| Group | Seed | Best epoch | Mean validation macro-F1 |
|---|---|---|---|
| no auxiliary (description only) | 0 | 4 | 0.664 |
| no auxiliary (description only) | 1 | 3 | 0.668 |
| no auxiliary (description only) | 2 | 4 | 0.656 |
| v3.1 auxiliary (description only) | 0 | 4 | 0.694 |
| v3.1 auxiliary (description only) | 1 | 4 | 0.697 |
| v3.1 auxiliary (description only) | 2 | 3 | 0.697 |
| CWE auxiliary (description only) | 0 | 4 | 0.663 |
| CWE auxiliary (description only) | 1 | 4 | 0.667 |
| CWE auxiliary (description only) | 2 | 3 | 0.666 |
| no auxiliary (W4, description + CWE) | 0 | 3 | 0.665 |
| no auxiliary (W4, description + CWE) | 1 | 4 | 0.646 |
| no auxiliary (W4, description + CWE) | 2 | 4 | 0.662 |
| v3.1 auxiliary (W4, description + CWE) | 0 | 4 | 0.695 |
| v3.1 auxiliary (W4, description + CWE) | 1 | 3 | 0.690 |
| v3.1 auxiliary (W4, description + CWE) | 2 | 3 | 0.702 |

## Coverage of the CWE supervision (CWE auxiliary runs; class table built on the training part only)

| Seed | v4 training samples | Auxiliary samples | v4 samples with a CWE | Auxiliary samples with a CWE | Share of 'other' among samples with a CWE | Top 5 CWEs |
|---|---|---|---|---|---|---|
| 0 | 14,488 | 60,000 | 99.9% | 86.4% | 17.8% | CWE-79, CWE-89, CWE-352, CWE-862, CWE-787 |
| 1 | 14,488 | 60,000 | 99.9% | 86.3% | 17.8% | CWE-79, CWE-89, CWE-862, CWE-352, CWE-22 |
| 2 | 14,488 | 60,000 | 99.9% | 86.4% | 17.9% | CWE-79, CWE-89, CWE-862, CWE-352, CWE-22 |
