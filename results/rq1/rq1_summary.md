## 1. By publication year (CVE List V5 snapshot, PUBLISHED records)

| Year | CVEs | CNA gives v4.0 | CNA gives v3.1 | CNA gives both | ADP gives v3.1 | ADP gives v4.0 | No v3.1/v4.0 at all |
|---|---|---|---|---|---|---|---|
| 2016 | 6,457 | 0 (0.0%) | 2 (0.0%) | 0 | 81 | 0 | 6,374 (98.7%) |
| 2017 | 14,642 | 3 (0.0%) | 13 (0.1%) | 3 | 216 | 0 | 14,413 (98.4%) |
| 2018 | 16,510 | 0 (0.0%) | 20 (0.1%) | 0 | 189 | 0 | 16,301 (98.7%) |
| 2019 | 17,308 | 0 (0.0%) | 335 (1.9%) | 0 | 220 | 0 | 16,754 (96.8%) |
| 2020 | 18,363 | 5 (0.0%) | 3,165 (17.2%) | 1 | 249 | 0 | 14,947 (81.4%) |
| 2021 | 20,177 | 10 (0.0%) | 6,395 (31.7%) | 6 | 340 | 0 | 13,441 (66.6%) |
| 2022 | 24,998 | 30 (0.1%) | 8,686 (34.7%) | 26 | 4,084 | 0 | 12,231 (48.9%) |
| 2023 | 28,847 | 53 (0.2%) | 16,162 (56.0%) | 50 | 6,008 | 0 | 6,841 (23.7%) |
| 2024 | 39,924 | 3,577 (9.0%) | 25,019 (62.7%) | 2,555 | 10,339 | 0 | 4,065 (10.2%) |
| 2025 | 48,153 | 12,419 (25.8%) | 30,931 (64.2%) | 7,755 | 9,044 | 1 | 3,948 (8.2%) |
| 2026 | 70,179 | 21,900 (31.2%) | 46,333 (66.0%) | 13,077 | 12,061 | 2 | 4,305 (6.1%) |

All years: CVEs with a CNA-provided v4.0 vector **37,997**; with CNA-provided v3.1 and v4.0 vectors **23,473**; with an ADP-provided v4.0 vector 3.

## 2. Sources of the v4.0 labels (CNA shortName, 300 in total)

| Source | CVEs | Share |
|---|---|---|
| VulDB | 12,882 | 33.9% |
| VulnCheck | 7,429 | 19.6% |
| GitHub_M | 5,129 | 13.5% |
| icscert | 861 | 2.3% |
| siemens | 619 | 1.6% |
| intel | 566 | 1.5% |
| INCIBE | 552 | 1.5% |
| CERT-PL | 469 | 1.2% |
| jpcert | 434 | 1.1% |
| EEF | 312 | 0.8% |
| qnap | 310 | 0.8% |
| juniper | 273 | 0.7% |

Top three sources per year:
- 2017 (3 CVEs): siemens 100.0%
- 2020 (5 CVEs): Google 80.0%; siemens 20.0%
- 2021 (10 CVEs): siemens 40.0%; Philips 30.0%; Nozomi 20.0%
- 2022 (30 CVEs): siemens 56.7%; VulDB 20.0%; Google 10.0%
- 2023 (53 CVEs): VulDB 41.5%; siemens 32.1%; Nozomi 20.8%
- 2024 (3,577 CVEs): VulDB 50.4%; GitHub_M 7.3%; siemens 5.8%
- 2025 (12,419 CVEs): VulDB 47.5%; GitHub_M 10.2%; VulnCheck 8.4%
- 2026 (21,900 CVEs): VulnCheck 29.2%; VulDB 23.5%; GitHub_M 16.4%

## 3. Several v4.0 labels for the same CVE

- CNA container with ≥2 different v4.0 base vectors: 57 CVEs
- Both the CNA and an ADP give a v4.0 vector: 0 CVEs

## 4. v3.1–v4.0 pairs given by the same CNA (23,473 pairs)

| Corresponding metrics | Agreement |
|---|---|
| v3.1 AV → v4.0 AV | 99.2% |
| v3.1 AC → v4.0 AC | 97.9% |
| v3.1 PR → v4.0 PR | 98.6% |
| v3.1 C → v4.0 VC | 96.3% |
| v3.1 I → v4.0 VI | 96.5% |
| v3.1 A → v4.0 VA | 98.6% |

Conditional distributions:
- v3.1 UI=N (n=19,257) → UI:N:97.8%, UI:P:1.1%, UI:A:1.1%
- v3.1 UI=R (n=4,216) → UI:P:67.3%, UI:A:21.0%, UI:N:11.6%
- v3.1 AC=H (n=1,962) → AT:N:53.6%, AT:P:46.4%
- v3.1 AC=L (n=21,511) → AT:N:96.8%, AT:P:3.2%
- v3.1 S=C (n=2,089) → subsequent impacts≠N:91.0%, subsequent impacts=N:9.0%
- v3.1 S=U (n=21,384) → subsequent impacts=N:97.7%, subsequent impacts≠N:2.3%

Exact-vector hit rate of conversion rule R: all 81.3%; by source (at least 100 pairs):

| Source | Pairs | Exact hit of R |
|---|---|---|
| VulDB | 12,882 | 96.5% |
| VulnCheck | 6,304 | 67.7% |
| icscert | 728 | 74.0% |
| siemens | 619 | 65.1% |
| intel | 460 | 19.6% |
| juniper | 273 | 21.2% |
| twcert | 257 | 86.4% |
| mongodb | 209 | 57.9% |
| f5 | 182 | 57.1% |
| AMZN | 181 | 43.6% |
| cisa-cg | 171 | 62.6% |
| ABB | 129 | 25.6% |
| jpcert | 128 | 50.0% |
| CERTVDE | 103 | 92.2% |

## 5. Value distribution of each v4.0 metric (the CNA's first v4.0 vector)

- AV: N=81.2%, L=14.2%, A=3.8%, P=0.8%
- AC: L=91.9%, H=8.1%
- AT: N=86.8%, P=13.2%
- PR: N=49.7%, L=40.6%, H=9.7%
- UI: N=79.1%, P=13.6%, A=7.3%
- VC: H=37.6%, L=33.1%, N=29.3%
- VI: L=37.6%, H=32.8%, N=29.6%
- VA: N=38.4%, H=32.5%, L=29.1%
- SC: N=83.6%, L=8.2%, H=8.1%
- SI: N=84.7%, L=8.2%, H=7.1%
- SA: N=90.7%, H=6.0%, L=3.3%

## 6. Text and CWE (v4.0 subset)

- Description length (characters): median 385, P10 228, P90 701; missing descriptions 0
- With a CWE (CNA or ADP): 99.6%