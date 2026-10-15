# Stability of the LLM baseline over repeated runs (the same 200 CVEs, 2 runs, generated automatically)

- Identical settings in every run: deepseek-v4-pro, AutoCVSS DTD prompt, thinking mode disabled, sampling temperature 0.0
- The standard deviation reflects only the randomness of the LLM's sampling, not the sampling error of drawing other CVEs

## Metrics: each run and mean ± standard deviation

| Scope | Run | meanF1 | exact | MAE | band | under | HC-rec |
|---|---|---|---|---|---|---|---|
| overall (n=200) | main | 0.519 | 0.050 | 1.790 | 0.355 | 0.150 | 0.848 |
| overall (n=200) | rep1 | 0.514 | 0.050 | 1.808 | 0.365 | 0.145 | 0.848 |
| overall (n=200) | **mean ± sd** | 0.517 ± 0.003 | 0.050 ± 0.000 | 1.799 ± 0.012 | 0.360 ± 0.007 | 0.147 ± 0.004 | 0.848 ± 0.000 |
| derived (n=30) | main | 0.400 | 0.067 | 2.937 | 0.100 | 0.033 | 1.000 |
| derived (n=30) | rep1 | 0.394 | 0.067 | 3.013 | 0.100 | 0.033 | 1.000 |
| derived (n=30) | **mean ± sd** | 0.397 ± 0.004 | 0.067 ± 0.000 | 2.975 ± 0.054 | 0.100 ± 0.000 | 0.033 ± 0.000 | 1.000 ± 0.000 |
| independent (n=70) | main | 0.564 | 0.043 | 1.204 | 0.471 | 0.143 | 0.880 |
| independent (n=70) | rep1 | 0.556 | 0.043 | 1.191 | 0.514 | 0.129 | 0.880 |
| independent (n=70) | **mean ± sd** | 0.560 ± 0.005 | 0.043 ± 0.000 | 1.198 ± 0.009 | 0.493 ± 0.030 | 0.136 ± 0.010 | 0.880 ± 0.000 |
| v4_only (n=50) | main | 0.472 | 0.040 | 1.754 | 0.400 | 0.160 | 0.917 |
| v4_only (n=50) | rep1 | 0.468 | 0.040 | 1.754 | 0.420 | 0.160 | 0.917 |
| v4_only (n=50) | **mean ± sd** | 0.470 ± 0.003 | 0.040 ± 0.000 | 1.754 ± 0.000 | 0.410 ± 0.014 | 0.160 ± 0.000 | 0.917 ± 0.000 |
| other (n=50) | main | 0.490 | 0.060 | 1.958 | 0.300 | 0.220 | 0.704 |
| other (n=50) | rep1 | 0.489 | 0.060 | 2.000 | 0.260 | 0.220 | 0.704 |
| other (n=50) | **mean ± sd** | 0.490 ± 0.000 | 0.060 ± 0.000 | 1.979 ± 0.030 | 0.280 ± 0.028 | 0.220 ± 0.000 | 0.704 ± 0.000 |

## Agreement of the raw answers

Share of (CVE, metric) with the same answer in all runs (DONT_KNOW counts as an answer):

| Metric | AV | AC | AT | PR | UI | VC | VI | VA | SC | SI | SA | Mean |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Same in all 2 runs | 1.000 | 1.000 | 0.995 | 0.990 | 0.995 | 0.955 | 0.995 | 0.990 | 0.925 | 0.940 | 0.965 | 0.977 |
| Pairwise agreement (mean) | 1.000 | 1.000 | 0.995 | 0.990 | 0.995 | 0.955 | 0.995 | 0.990 | 0.925 | 0.940 | 0.965 | 0.977 |

- Share of CVEs with the same complete vector: same in all 2 runs 0.825; pairwise mean 0.825
- Share of CVEs with the same severity band: same in all 2 runs 0.935; pairwise mean 0.935
- Share of DONT_KNOW answers (or failed requests) in each run: {'main': 0.077, 'rep1': 0.081}
