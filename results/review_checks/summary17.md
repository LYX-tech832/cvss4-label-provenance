# Assessor and version in the NVD reference, α selected by expected cost, additional rows of the main results table (generated automatically)

## A. The CNA's v3.1 vector and its v4.0 vector, each against the NVD's v3.1 vector, on the same CVEs

Scope: CVEs with a CNA v3.1, a CNA v4.0 and an NVD v3.1 vector, 8,410 in total. Each cell: share with the same value as the NVD. "All 7 equal" excludes Scope; "vector equal" means all 8 v3.1 metrics are equal (the same definition as the 3.1% / 14.2% / 28.4% in Note S9).

| Source | n | Comparison | AV | AC | PR | UI | C | I | A | All 7 equal | Scope | Vector equal | Same band | CNA lower / higher |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| VulDB (derived) | 6,954 | CNA v3.1 vs NVD v3.1 | 0.992 | 0.995 | 0.767 | 0.992 | 0.119 | 0.286 | 0.259 | 0.035 | 0.845 | 0.031 | 0.112 | 0.885 / 0.004 |
| | | CNA v4.0 vs NVD v3.1 | 0.992 | 0.995 | 0.767 | 0.934 | 0.119 | 0.286 | 0.259 | 0.033 | — | — | 0.253 | 0.739 / 0.007 |
| | | difference (v4.0 − v3.1) | +0.000 | +0.000 | +0.000 | -0.058 | +0.000 | +0.000 | +0.000 | -0.002 | — | — | +0.142 | — |
| VulnCheck | 731 | CNA v3.1 vs NVD v3.1 | 0.917 | 0.832 | 0.754 | 0.825 | 0.854 | 0.806 | 0.770 | 0.163 | 0.945 | 0.142 | 0.606 | 0.301 / 0.093 |
| | | CNA v4.0 vs NVD v3.1 | 0.936 | 0.859 | 0.728 | 0.921 | 0.847 | 0.811 | 0.731 | 0.248 | — | — | 0.661 | 0.269 / 0.070 |
| | | difference (v4.0 − v3.1) | +0.019 | +0.027 | -0.026 | +0.096 | -0.007 | +0.005 | -0.040 | +0.085 | — | — | +0.055 | — |
| GitHub | 0 | fewer than 30, not listed | | | | | | | | | | | | |
| other sources | 725 | CNA v3.1 vs NVD v3.1 | 0.948 | 0.806 | 0.848 | 0.901 | 0.829 | 0.839 | 0.766 | 0.354 | 0.836 | 0.284 | 0.643 | 0.265 / 0.092 |
| | | CNA v4.0 vs NVD v3.1 | 0.943 | 0.797 | 0.850 | 0.888 | 0.822 | 0.823 | 0.759 | 0.324 | — | — | 0.632 | 0.240 / 0.128 |
| | | difference (v4.0 − v3.1) | -0.004 | -0.008 | +0.001 | -0.012 | -0.007 | -0.015 | -0.007 | -0.030 | — | — | -0.011 | — |
| non-derived total | 1,456 | CNA v3.1 vs NVD v3.1 | 0.932 | 0.819 | 0.801 | 0.863 | 0.841 | 0.822 | 0.768 | 0.258 | 0.891 | 0.213 | 0.624 | 0.283 / 0.093 |
| | | CNA v4.0 vs NVD v3.1 | 0.940 | 0.828 | 0.788 | 0.905 | 0.834 | 0.817 | 0.745 | 0.286 | — | — | 0.646 | 0.255 / 0.099 |
| | | difference (v4.0 − v3.1) | +0.008 | +0.010 | -0.012 | +0.042 | -0.007 | -0.005 | -0.023 | +0.027 | — | — | +0.022 | — |

Share of the same CNA's v4.0 vectors equal to its own v3.1 vectors on the 7 items (how much changes between versions):

| Source | n | AV | AC | PR | UI | C | I | A | All 7 equal |
|---|---|---|---|---|---|---|---|---|---|
| VulDB (derived) | 6,954 | 1.000 | 1.000 | 1.000 | 0.940 | 1.000 | 1.000 | 1.000 | 0.940 |
| VulnCheck | 731 | 0.967 | 0.962 | 0.947 | 0.863 | 0.947 | 0.978 | 0.923 | 0.741 |
| other sources | 725 | 0.994 | 0.890 | 0.990 | 0.988 | 0.975 | 0.975 | 0.957 | 0.817 |
| non-derived total | 1,456 | 0.981 | 0.926 | 0.968 | 0.925 | 0.961 | 0.977 | 0.940 | 0.779 |

## B. α selected on the validation set by cost ratio (r per underestimate, 1 per overestimate; temporal split)

Each cell: α selected on the validation set / test cost at that α / test cost of argmax / (the α with the lowest test cost and its cost, for comparison only). DeBERTa + auxiliary task selects α per seed; the cost is averaged over the 5 seeds, and the α column lists the value selected for each of the 5 seeds.

| Method | r = 1 | r = 2 | r = 5 | r = 10 |
|---|---|---|---|---|
| DeBERTa + v3.1 auxiliary | α = 1.0, 1.0, 1.0, 1.0, 1.0 / 0.377 / 0.377 / (1.0: 0.377) | α = 0.4, 0.9, 0.8, 0.6, 0.4 / 0.493 / 0.520 / (0.5: 0.491) | α = 0.3, 0.4, 0.4, 0.3, 0.3 / 0.684 / 0.950 / (0.3: 0.675) | α = 0.3, 0.3, 0.3, 0.3, 0.3 / 0.962 / 1.666 / (0.3: 0.962) |
| TF-IDF + LR | α = 1.0 / 0.402 / 0.402 / (1.0: 0.402) | α = 0.6 / 0.507 / 0.538 / (0.6: 0.507) | α = 0.4 / 0.666 / 0.948 / (0.3: 0.656) | α = 0.3 / 0.830 / 1.630 / (0.3: 0.830) |
| TF-IDF pipeline (rule R) | α = 1.0 / 0.459 / 0.459 / (1.0: 0.459) | α = 1.0 / 0.586 / 0.586 / (0.8: 0.582) | α = 0.4 / 0.767 / 0.967 / (0.3: 0.754) | α = 0.3 / 0.918 / 1.602 / (0.3: 0.918) |

(The validation values of TF-IDF and the pipeline come from models fitted only on the first 90% of the training part, the test values from models fitted on the whole training part; see risk_decode_baselines.py.)

## C. Additional rows of the main results table (temporal split; mean over seeds)


### all (21,900)

| Method | Macro-F1 | v4-F1 | Exact | MAE | Band | Under | H+C rec. | Seeds |
|---|---|---|---|---|---|---|---|---|
| DeBERTa (selected 25 epochs, seeds 0–4; check) | 0.620 | 0.549 | 0.208 | 1.269 | 0.604 | 0.157 | 0.807 | 5 |
| DeBERTa + v3.1 aux. (seeds 0–4; check) | 0.645 | 0.563 | 0.237 | 1.174 | 0.623 | 0.143 | 0.816 | 5 |
| rule-R pseudo-labels (seeds 0–2) | 0.643 | 0.557 | 0.242 | 1.130 | 0.635 | 0.130 | 0.833 | 3 |
| sequential fine-tuning, 25 epochs (seeds 0–2) | 0.645 | 0.564 | 0.237 | 1.235 | 0.627 | 0.150 | 0.822 | 3 |
| DeBERTa pipeline (seeds 0–2) | 0.601 | 0.492 | 0.219 | 1.138 | 0.622 | 0.111 | 0.858 | 3 |
| SecureBERT (seeds 0–4) | 0.639 | 0.565 | 0.215 | 1.237 | 0.615 | 0.149 | 0.820 | 5 |
| SecureBERT + v3.1 aux. (seeds 0–4) | 0.652 | 0.571 | 0.242 | 1.143 | 0.635 | 0.148 | 0.811 | 5 |

### non-derived (16,749)

| Method | Macro-F1 | v4-F1 | Exact | MAE | Band | Under | H+C rec. | Seeds |
|---|---|---|---|---|---|---|---|---|
| DeBERTa (selected 25 epochs, seeds 0–4; check) | 0.564 | 0.533 | 0.134 | 1.439 | 0.513 | 0.184 | 0.816 | 5 |
| DeBERTa + v3.1 aux. (seeds 0–4; check) | 0.590 | 0.547 | 0.165 | 1.321 | 0.537 | 0.165 | 0.826 | 5 |
| rule-R pseudo-labels (seeds 0–2) | 0.594 | 0.545 | 0.173 | 1.265 | 0.552 | 0.148 | 0.845 | 3 |
| sequential fine-tuning, 25 epochs (seeds 0–2) | 0.588 | 0.547 | 0.168 | 1.395 | 0.542 | 0.175 | 0.832 | 3 |
| DeBERTa pipeline (seeds 0–2) | 0.565 | 0.483 | 0.193 | 1.198 | 0.561 | 0.126 | 0.861 | 3 |
| SecureBERT (seeds 0–4) | 0.579 | 0.547 | 0.142 | 1.394 | 0.528 | 0.170 | 0.830 | 5 |
| SecureBERT + v3.1 aux. (seeds 0–4) | 0.599 | 0.556 | 0.172 | 1.280 | 0.553 | 0.171 | 0.820 | 5 |
