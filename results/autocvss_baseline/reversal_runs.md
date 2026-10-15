# Ranking reversal and the LLM's sampling randomness (the same 2,000 test CVEs, three runs of DeepSeek-V4-Pro; generated automatically)


## whole sample (n = 2,000): DeepSeek − TF-IDF

| Run | Mean macro-F1 difference | Band accuracy difference |
|---|---|---|
| main run (26 Sep) | -0.031 | -0.137 |
| full repetition 1 (3 Oct) | -0.037 | -0.155 |
| full repetition 2 (3 Oct) | -0.031 | -0.165 |
| Standard deviation over the three runs | 0.0030 | 0.0142 |

| Estimate | Mean macro-F1 difference | Band accuracy difference |
|---|---|---|
| Main run only, CVEs resampled | -0.031 [-0.047, -0.016] | -0.137 [-0.164, -0.111] |
| Mean of the three runs, CVEs resampled | -0.033 [-0.047, -0.020] | -0.152 [-0.177, -0.127] |
| Mean of the three runs, CVEs and runs resampled (two levels) | -0.033 [-0.047, -0.018] | -0.152 [-0.181, -0.122] |

## without derived labels (n = 1,700): DeepSeek − TF-IDF

| Run | Mean macro-F1 difference | Band accuracy difference |
|---|---|---|
| main run (26 Sep) | +0.021 | -0.037 |
| full repetition 1 (3 Oct) | +0.018 | -0.053 |
| full repetition 2 (3 Oct) | +0.023 | -0.066 |
| Standard deviation over the three runs | 0.0026 | 0.0144 |

| Estimate | Mean macro-F1 difference | Band accuracy difference |
|---|---|---|
| Main run only, CVEs resampled | +0.021 [+0.006, +0.037] | -0.037 [-0.068, -0.007] |
| Mean of the three runs, CVEs resampled | +0.021 [+0.007, +0.036] | -0.052 [-0.078, -0.025] |
| Mean of the three runs, CVEs and runs resampled (two levels) | +0.021 [+0.005, +0.036] | -0.052 [-0.081, -0.021] |

## Agreement between runs (all 2,000 CVEs)

| Pair of runs | Same severity band | Same complete vector |
|---|---|---|
| main run (26 Sep) / full repetition 1 (3 Oct) | 65.9% | 19.1% |
| main run (26 Sep) / full repetition 2 (3 Oct) | 64.8% | 18.8% |
| full repetition 1 (3 Oct) / full repetition 2 (3 Oct) | 64.3% | 18.2% |
