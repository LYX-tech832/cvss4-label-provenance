# Records with several vectors and seed uncertainty (generated automatically)

## 1. Records with several vectors

Records of the v4.0 dataset whose CNA gave several v4.0 vectors: 57; records with a v4.0 vector whose CNA gave several v3.1 vectors: 18; together (deduplicated) 72; of these, 41 are in the temporal split test set and 31 in the training and validation parts.

Change of mean macro-F1 / band accuracy when these test CVEs are excluded (models not retrained; these records are used as usual in training):

| Method | All: original → excluded | Non-derived: original → excluded |
|---|---|---|
| TF-IDF + LR | 0.605 / 0.598 → 0.605 / 0.598 | 0.547 / 0.504 → 0.547 / 0.504 |
| DeBERTa (5 seeds) | 0.605 / 0.569 → 0.605 / 0.569 | 0.534 / 0.468 → 0.534 / 0.468 |
| DeBERTa + auxiliary task (5 seeds) | 0.645 / 0.623 → 0.645 / 0.623 | 0.590 / 0.537 → 0.589 / 0.537 |

Sources of these records in the test set (top 8): palo_alto 16; f5 12; RTI 6; VulnCheck 3; Temporal 2; NCSC.ch 1; OpenVPN 1


## 2. LOSO: per-seed differences auxiliary 5 epochs − baseline 10 epochs (mean macro-F1)

| Held out | Per-seed differences (seeds 0–4) | Mean | t interval (4 degrees of freedom) | Positive seeds |
|---|---|---|---|---|
| VulnCheck | +0.016, +0.028, +0.019, +0.021, +0.022 | +0.021 | [+0.016, +0.027] | 5 |
| GitHub_M | +0.017, +0.014, +0.027, +0.029, +0.010 | +0.019 | [+0.009, +0.030] | 5 |
| VulDB | +0.010, +0.013, +0.043, +0.031, +0.064 | +0.032 | [+0.005, +0.060] | 5 |
