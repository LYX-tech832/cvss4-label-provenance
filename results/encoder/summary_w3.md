# W3 GPU runs (DeBERTa-v3-base, seed 0, single run)

Columns: mean F1 | exact vector | score MAE | band accuracy | underestimation rate | High+Critical recall

## A. All test labels

| Setting | Method | Mean F1 | Exact | MAE | Band accuracy | Underestimation | HC recall |
|---|---|---|---|---|---|---|---|
| T2_temporal | CPU baseline tfidf_lr | 0.605 | 0.237 | 1.334 | 0.598 | 0.136 | 0.854 |
| T2_temporal | DeBERTa crowd | 0.577 | 0.221 | 1.331 | 0.577 | 0.109 | 0.875 |
| T2_temporal | DeBERTa feature | 0.577 | 0.217 | 1.345 | 0.556 | 0.096 | 0.891 |
| T2_temporal | DeBERTa none_aux | 0.637 | 0.261 | 1.168 | 0.631 | 0.133 | 0.833 |
| T2_temporal | DeBERTa none | 0.577 | 0.224 | 1.339 | 0.570 | 0.105 | 0.883 |
| T2_loso-VulnCheck | CPU baseline tfidf_lr | 0.562 | 0.225 | 1.133 | 0.572 | 0.104 | 0.920 |
| T2_loso-VulnCheck | DeBERTa none_aux | 0.607 | 0.278 | 0.908 | 0.637 | 0.108 | 0.889 |
| T2_loso-VulnCheck | DeBERTa none | 0.548 | 0.260 | 0.994 | 0.611 | 0.103 | 0.916 |
| T2_loso-GitHub_M | CPU baseline tfidf_lr | 0.481 | 0.110 | 1.659 | 0.484 | 0.226 | 0.775 |
| T2_loso-GitHub_M | DeBERTa none_aux | 0.525 | 0.145 | 1.454 | 0.504 | 0.160 | 0.853 |
| T2_loso-GitHub_M | DeBERTa none | 0.488 | 0.128 | 1.579 | 0.479 | 0.169 | 0.845 |
| T2_loso-VulDB | CPU baseline tfidf_lr | 0.366 | 0.018 | 2.828 | 0.152 | 0.065 | 0.976 |
| T2_loso-VulDB | DeBERTa none_aux | 0.404 | 0.019 | 2.470 | 0.241 | 0.024 | 0.990 |
| T2_loso-VulDB | DeBERTa none | 0.351 | 0.009 | 3.004 | 0.091 | 0.018 | 0.994 |
| T1_temporal | CPU baseline rule_R | 0.865 | 0.801 | 0.143 | 0.951 | 0.009 | 0.988 |
| T1_temporal | DeBERTa none | 0.775 | 0.652 | 0.325 | 0.885 | 0.039 | 0.951 |

## B. By label type (T2 temporal split; mean F1 / v4-specific F1 / band accuracy / underestimation rate)

| Method | derived | independent | v4_only | other |
|---|---|---|---|---|
| CPU baseline TF-IDF+LR | 0.624 / 0.420 / 0.904 / 0.074 | 0.580 / 0.551 / 0.572 / 0.096 | 0.488 / 0.451 / 0.436 / 0.237 | 0.524 / 0.478 / 0.466 / 0.171 |
| DeBERTa crowd | 0.610 / 0.421 / 0.900 / 0.068 | 0.533 / 0.549 / 0.535 / 0.091 | 0.477 / 0.468 / 0.432 / 0.147 | 0.481 / 0.474 / 0.436 / 0.143 |
| DeBERTa feature | 0.614 / 0.421 / 0.906 / 0.069 | 0.517 / 0.540 / 0.483 / 0.070 | 0.469 / 0.462 / 0.406 / 0.128 | 0.488 / 0.490 / 0.437 / 0.132 |
| DeBERTa none_aux | 0.634 / 0.421 / 0.909 / 0.070 | 0.605 / 0.563 / 0.606 / 0.116 | 0.528 / 0.487 / 0.484 / 0.205 | 0.566 / 0.512 / 0.513 / 0.160 |
| DeBERTa none | 0.609 / 0.421 / 0.898 / 0.068 | 0.534 / 0.553 / 0.528 / 0.086 | 0.472 / 0.462 / 0.413 / 0.143 | 0.478 / 0.474 / 0.434 / 0.139 |

## C. Gain of the v3.1 auxiliary task (with − without, single run)

| Split | Δ mean F1 | Δ exact | Δ MAE | Δ band accuracy | Δ underestimation |
|---|---|---|---|---|---|
| temporal | +0.060 | +0.038 | -0.171 | +0.061 | +0.027 |
| loso-VulnCheck | +0.059 | +0.018 | -0.087 | +0.026 | +0.006 |
| loso-GitHub_M | +0.037 | +0.017 | -0.124 | +0.026 | -0.009 |
| loso-VulDB | +0.053 | +0.011 | -0.534 | +0.150 | +0.006 |