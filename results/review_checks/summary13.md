# The NVD's v3.1 assessments as a second, independent assessor (generated automatically)

Only the content both versions share is compared: AV, AC, PR; whether user interaction is required; C/I/A against max(V, S); the band is the NVD's v3.1 band against the CVSS-B band of the v4.0 vector.

## A. Coverage

CVEs with a CNA v4.0 label: 37,997, of which 16,250 have an NVD-assigned v3.1 vector (42.8%). Of the temporal split test set (published in 2026, 21,900 CVEs), 6,356 have one (29.0%).

| Source | v4.0 labels | With NVD v3.1 | Share | Of which in 2026 |
|---|---|---|---|---|
| VulDB (derived) | 12,882 | 6,954 | 54.0% | 922 |
| VulnCheck | 7,429 | 1,378 | 18.5% | 900 |
| GitHub | 5,129 | 3,147 | 61.4% | 2,156 |
| other sources | 12,557 | 4,771 | 38.0% | 2,378 |

## B. Agreement of each source's CNA v4.0 labels with the NVD (all CVEs with an NVD v3.1 vector)

| Source | n | AV | AC | PR | UI | C | I | A | All 7 items equal | Same band | CNA lower / higher |
|---|---|---|---|---|---|---|---|---|---|---|---|
| VulDB (derived) | 6,954 | 0.992 | 0.995 | 0.767 | 0.934 | 0.119 | 0.286 | 0.259 | 0.033 | 0.253 | 0.739 / 0.007 |
| VulnCheck | 1,378 | 0.954 | 0.914 | 0.800 | 0.943 | 0.873 | 0.836 | 0.790 | 0.425 | 0.693 | 0.211 / 0.096 |
| GitHub | 3,147 | 0.960 | 0.916 | 0.844 | 0.897 | 0.781 | 0.797 | 0.792 | 0.446 | 0.600 | 0.235 / 0.165 |
| other sources | 4,771 | 0.907 | 0.872 | 0.791 | 0.879 | 0.772 | 0.778 | 0.750 | 0.355 | 0.613 | 0.239 / 0.148 |
| all | 16,250 | 0.958 | 0.937 | 0.792 | 0.911 | 0.503 | 0.576 | 0.552 | 0.241 | 0.463 | 0.450 / 0.087 |
| non-derived total | 9,296 | 0.932 | 0.893 | 0.810 | 0.895 | 0.790 | 0.793 | 0.770 | 0.396 | 0.620 | 0.234 / 0.146 |

The NVD's v3.1 band distribution against the CNA's v4.0 band distribution (Low / Medium / High / Critical):
- VulDB (derived): NVD 0.01 / 0.24 / 0.31 / 0.44; CNA 0.02 / 0.94 / 0.05 / 0.00
- VulnCheck: NVD 0.01 / 0.44 / 0.37 / 0.18; CNA 0.03 / 0.48 / 0.37 / 0.12
- GitHub: NVD 0.01 / 0.41 / 0.38 / 0.20; CNA 0.04 / 0.41 / 0.40 / 0.15
- other sources: NVD 0.02 / 0.43 / 0.38 / 0.16; CNA 0.06 / 0.43 / 0.37 / 0.13

Share of the same CNA's v3.1 vectors that are identical to the NVD's v3.1 vectors (dual-scored CVEs): VulDB (derived) 3.1% (n = 6,954); VulnCheck 14.2% (n = 731); other sources 28.4% (n = 725).

## C. Results of each method against the NVD on the temporal split test set

Test CVEs with an NVD v3.1 vector: 6,356 (derived 922, non-derived 5,434). Agreement on the 7 items = mean agreement of the predicted v4.0 vector with the NVD on the 7 shared items; the last column is the band accuracy against the CNA labels on the same CVEs, for comparison.

| Scope | Method | Agreement on the 7 items (vs NVD) | Same band (vs NVD) | Lower than NVD | Band accuracy (vs CNA labels) |
|---|---|---|---|---|---|
| all (6,356) | TF-IDF + LR | 0.771 | 0.458 | 0.278 | 0.522 |
| all (6,356) | pipeline (rule R, no v4.0 labels) | 0.801 | 0.516 | 0.206 | 0.492 |
| all (6,356) | DeBERTa (25 epochs) | 0.750 | 0.463 | 0.295 | 0.541 |
| all (6,356) | DeBERTa + auxiliary | 0.781 | 0.490 | 0.276 | 0.559 |
| all (6,356) | the CNA's v4.0 labels themselves | 0.817 | 0.554 | 0.313 | — |
| derived (VulDB) (922) | TF-IDF + LR | 0.598 | 0.267 | 0.729 | 0.960 |
| derived (VulDB) (922) | pipeline (rule R, no v4.0 labels) | 0.691 | 0.345 | 0.467 | 0.516 |
| derived (VulDB) (922) | DeBERTa (25 epochs) | 0.598 | 0.270 | 0.721 | 0.955 |
| derived (VulDB) (922) | DeBERTa + auxiliary | 0.606 | 0.268 | 0.725 | 0.959 |
| derived (VulDB) (922) | the CNA's v4.0 labels themselves | 0.649 | 0.248 | 0.747 | — |
| non-derived (5,434) | TF-IDF + LR | 0.801 | 0.491 | 0.201 | 0.447 |
| non-derived (5,434) | pipeline (rule R, no v4.0 labels) | 0.820 | 0.545 | 0.162 | 0.488 |
| non-derived (5,434) | DeBERTa (25 epochs) | 0.776 | 0.495 | 0.222 | 0.470 |
| non-derived (5,434) | DeBERTa + auxiliary | 0.810 | 0.527 | 0.200 | 0.491 |
| non-derived (5,434) | the CNA's v4.0 labels themselves | 0.846 | 0.606 | 0.239 | — |

Paired differences (test CVEs resampled 1,000 times, 95% interval):

| A − B | Scope | Agreement on the 7 items (vs NVD) | Same band (vs NVD) | Band accuracy (vs CNA labels) |
|---|---|---|---|---|
| TF-IDF + LR − pipeline (rule R, no v4.0 labels) | all | -0.030 [-0.034, -0.025] | -0.057 [-0.071, -0.045] | +0.030 [+0.016, +0.045] |
| TF-IDF + LR − pipeline (rule R, no v4.0 labels) | derived (VulDB) | -0.093 [-0.105, -0.081] | -0.078 [-0.113, -0.042] | +0.444 [+0.410, +0.475] |
| TF-IDF + LR − pipeline (rule R, no v4.0 labels) | non-derived | -0.019 [-0.023, -0.015] | -0.054 [-0.069, -0.038] | -0.040 [-0.055, -0.026] |
| DeBERTa + auxiliary − pipeline (rule R, no v4.0 labels) | all | -0.020 [-0.024, -0.017] | -0.026 [-0.039, -0.013] | +0.067 [+0.054, +0.080] |
| DeBERTa + auxiliary − pipeline (rule R, no v4.0 labels) | derived (VulDB) | -0.085 [-0.097, -0.073] | -0.077 [-0.113, -0.041] | +0.443 [+0.410, +0.475] |
| DeBERTa + auxiliary − pipeline (rule R, no v4.0 labels) | non-derived | -0.009 [-0.014, -0.006] | -0.017 [-0.030, -0.005] | +0.004 [-0.009, +0.016] |
| DeBERTa + auxiliary − DeBERTa (25 epochs) | all | +0.030 [+0.028, +0.032] | +0.027 [+0.021, +0.034] | +0.018 [+0.012, +0.025] |
| DeBERTa + auxiliary − DeBERTa (25 epochs) | derived (VulDB) | +0.008 [+0.005, +0.010] | -0.002 [-0.006, +0.002] | +0.004 [-0.000, +0.008] |
| DeBERTa + auxiliary − DeBERTa (25 epochs) | non-derived | +0.034 [+0.032, +0.036] | +0.032 [+0.024, +0.039] | +0.021 [+0.013, +0.028] |

## D. CVEs of the LLM sample with an NVD v3.1 vector

642 CVEs (derived 62, non-derived 580).

| Scope | Method | Agreement on the 7 items (vs NVD) | Same band (vs NVD) | Lower / higher than NVD | Band accuracy (vs CNA labels) |
|---|---|---|---|---|---|
| derived (VulDB) (62) | AutoCVSS + DeepSeek-V4-Pro | 0.820 | 0.565 | 0.113 / 0.323 | 0.129 |
| derived (VulDB) (62) | AutoCVSS + Qwen3-8B | 0.664 | 0.210 | 0.613 / 0.177 | 0.081 |
| derived (VulDB) (62) | TF-IDF + LR | 0.588 | 0.306 | 0.694 / 0.000 | 0.952 |
| derived (VulDB) (62) | DeBERTa + auxiliary | 0.588 | 0.297 | 0.703 / 0.000 | 0.961 |
| derived (VulDB) (62) | the CNA's v4.0 labels themselves | 0.643 | 0.258 | 0.742 / 0.000 | — |
| non-derived (580) | AutoCVSS + DeepSeek-V4-Pro | 0.808 | 0.398 | 0.183 / 0.419 | 0.402 |
| non-derived (580) | AutoCVSS + Qwen3-8B | 0.675 | 0.324 | 0.453 / 0.222 | 0.310 |
| non-derived (580) | TF-IDF + LR | 0.797 | 0.483 | 0.186 / 0.331 | 0.416 |
| non-derived (580) | DeBERTa + auxiliary | 0.809 | 0.520 | 0.203 / 0.277 | 0.473 |
| non-derived (580) | the CNA's v4.0 labels themselves | 0.849 | 0.603 | 0.229 / 0.167 | — |
