# Stability of the LLM baseline over repeated runs (the same 200 CVEs, 3 runs, generated automatically)

- Identical settings in every run: deepseek-v4-pro, AutoCVSS DTD prompt, thinking mode disabled, sampling temperature API default (not set by AutoCVSS)
- The standard deviation reflects only the randomness of the LLM's sampling, not the sampling error of drawing other CVEs

## Metrics: each run and mean ± standard deviation

| Scope | Run | meanF1 | exact | MAE | band | under | HC-rec |
|---|---|---|---|---|---|---|---|
| overall (n=200) | main | 0.522 | 0.040 | 1.604 | 0.430 | 0.115 | 0.857 |
| overall (n=200) | rep1 | 0.501 | 0.055 | 1.811 | 0.365 | 0.160 | 0.857 |
| overall (n=200) | rep2 | 0.522 | 0.060 | 1.590 | 0.405 | 0.100 | 0.895 |
| overall (n=200) | **mean ± sd** | 0.515 ± 0.012 | 0.052 ± 0.010 | 1.668 ± 0.124 | 0.400 ± 0.033 | 0.125 ± 0.031 | 0.870 ± 0.022 |
| derived (n=30) | main | 0.401 | 0.000 | 3.030 | 0.100 | 0.000 | 1.000 |
| derived (n=30) | rep1 | 0.412 | 0.033 | 2.940 | 0.100 | 0.067 | 1.000 |
| derived (n=30) | rep2 | 0.405 | 0.067 | 2.693 | 0.200 | 0.000 | 1.000 |
| derived (n=30) | **mean ± sd** | 0.406 ± 0.006 | 0.033 ± 0.033 | 2.888 ± 0.174 | 0.133 ± 0.058 | 0.022 ± 0.038 | 1.000 ± 0.000 |
| independent (n=70) | main | 0.543 | 0.000 | 1.033 | 0.529 | 0.129 | 0.860 |
| independent (n=70) | rep1 | 0.521 | 0.029 | 1.327 | 0.443 | 0.157 | 0.880 |
| independent (n=70) | rep2 | 0.529 | 0.071 | 1.060 | 0.471 | 0.100 | 0.900 |
| independent (n=70) | **mean ± sd** | 0.531 ± 0.011 | 0.033 ± 0.036 | 1.140 ± 0.163 | 0.481 ± 0.044 | 0.129 ± 0.029 | 0.880 ± 0.020 |
| v4_only (n=50) | main | 0.504 | 0.100 | 1.564 | 0.540 | 0.100 | 0.958 |
| v4_only (n=50) | rep1 | 0.475 | 0.080 | 1.786 | 0.420 | 0.160 | 0.917 |
| v4_only (n=50) | rep2 | 0.509 | 0.060 | 1.600 | 0.460 | 0.140 | 0.875 |
| v4_only (n=50) | **mean ± sd** | 0.496 ± 0.019 | 0.080 ± 0.020 | 1.650 ± 0.119 | 0.473 ± 0.061 | 0.133 ± 0.031 | 0.917 ± 0.042 |
| other (n=50) | main | 0.483 | 0.060 | 1.588 | 0.380 | 0.180 | 0.741 |
| other (n=50) | rep1 | 0.478 | 0.080 | 1.838 | 0.360 | 0.220 | 0.741 |
| other (n=50) | rep2 | 0.503 | 0.040 | 1.658 | 0.380 | 0.120 | 0.889 |
| other (n=50) | **mean ± sd** | 0.488 ± 0.013 | 0.060 ± 0.020 | 1.695 ± 0.129 | 0.373 ± 0.012 | 0.173 ± 0.050 | 0.790 ± 0.086 |

## Agreement of the raw answers

Share of (CVE, metric) with the same answer in all runs (DONT_KNOW counts as an answer):

| Metric | AV | AC | AT | PR | UI | VC | VI | VA | SC | SI | SA | Mean |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Same in all 3 runs | 0.950 | 0.935 | 0.745 | 0.820 | 0.800 | 0.615 | 0.700 | 0.700 | 0.495 | 0.495 | 0.555 | 0.710 |
| Pairwise agreement (mean) | 0.967 | 0.957 | 0.827 | 0.877 | 0.863 | 0.720 | 0.783 | 0.793 | 0.647 | 0.650 | 0.690 | 0.798 |

- Share of CVEs with the same complete vector: same in all 3 runs 0.075; pairwise mean 0.158
- Share of CVEs with the same severity band: same in all 3 runs 0.525; pairwise mean 0.662
- Share of DONT_KNOW answers (or failed requests) in each run: {'main': 0.105, 'rep1': 0.095, 'rep2': 0.11}
