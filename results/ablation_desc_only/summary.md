# Control: TF-IDF+LR on the description only vs description + CWE identifier (T2 temporal split, generated automatically)

- Training 16,097 CVEs (before 2026), test 21,900 CVEs (2026); share with a CWE identifier: training 99.9%, test 99.4%
- Same hyperparameters as baselines_v0, only the input text differs; single run (logistic regression is deterministic)

| Scope | Input | meanF1 | v4F1 | exact | MAE | band | under | HC-rec |
|---|---|---|---|---|---|---|---|---|
| all test labels (n=21,900) | description + CWE | 0.605 | 0.522 | 0.237 | 1.334 | 0.598 | 0.136 | 0.854 |
| all test labels (n=21,900) | description only | 0.603 | 0.518 | 0.231 | 1.366 | 0.595 | 0.139 | 0.851 |
| derived (n=5,151) | description + CWE | 0.624 | 0.420 | 0.451 | 0.712 | 0.904 | 0.074 | 0.673 |
| derived (n=5,151) | description only | 0.620 | 0.419 | 0.435 | 0.718 | 0.904 | 0.074 | 0.671 |
| independent (n=7,242) | description + CWE | 0.580 | 0.551 | 0.236 | 1.112 | 0.572 | 0.096 | 0.924 |
| independent (n=7,242) | description only | 0.577 | 0.547 | 0.232 | 1.126 | 0.571 | 0.095 | 0.924 |
| v4_only (n=4,264) | description + CWE | 0.488 | 0.451 | 0.125 | 2.006 | 0.436 | 0.237 | 0.799 |
| v4_only (n=4,264) | description only | 0.482 | 0.444 | 0.118 | 2.115 | 0.427 | 0.250 | 0.784 |
| other (n=5,243) | description + CWE | 0.524 | 0.478 | 0.118 | 1.705 | 0.466 | 0.171 | 0.842 |
| other (n=5,243) | description only | 0.522 | 0.475 | 0.119 | 1.725 | 0.462 | 0.175 | 0.842 |
| with CWE (n=21,777) | description + CWE | 0.606 | 0.522 | 0.238 | 1.332 | 0.599 | 0.137 | 0.854 |
| with CWE (n=21,777) | description only | 0.604 | 0.518 | 0.232 | 1.364 | 0.596 | 0.140 | 0.850 |
| without CWE (n=123) | description + CWE | 0.498 | 0.515 | 0.024 | 1.763 | 0.431 | 0.065 | 0.921 |
| without CWE (n=123) | description only | 0.510 | 0.526 | 0.016 | 1.767 | 0.447 | 0.081 | 0.921 |
