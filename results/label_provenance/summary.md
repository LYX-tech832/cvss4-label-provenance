# Label provenance audit (all periods; sources with at least 100 same-source v3.1/v4.0 pairs)

| Source | v4 labels | Pairs | Distinct v3.1 vectors | R (UI:R→P, S:C copied) | UI:R→A | subsequent impacts always N | UI:R→A and subsequent always N | FD_in | **FD_oos** | det-AT | det-UI | det-SC | det-SI | det-SA |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| VulDB | 12,882 | 12,882 | 140 | 96.5% | 84.6% | 95.3% | 83.4% | 96.5% | **99.5%** | 100.0% | 96.5% | 100.0% | 100.0% | 100.0% |
| VulnCheck | 7,429 | 6,304 | 431 | 67.7% | 62.1% | 61.0% | 57.6% | 74.9% | **74.6%** | 93.3% | 91.2% | 97.9% | 98.0% | 98.7% |
| icscert | 861 | 728 | 181 | 74.0% | 77.5% | 69.5% | 72.8% | 87.1% | **77.2%** | 96.3% | 95.7% | 98.5% | 97.8% | 98.1% |
| siemens | 619 | 619 | 168 | 65.1% | 62.8% | 57.7% | 55.4% | 90.6% | **74.7%** | 95.8% | 97.9% | 98.5% | 98.9% | 99.0% |
| intel | 566 | 460 | 145 | 19.6% | 19.6% | 23.7% | 23.9% | 76.3% | **49.3%** | 86.3% | 95.9% | 93.5% | 95.0% | 92.4% |
| juniper | 273 | 273 | 56 | 21.2% | 19.8% | 19.4% | 19.0% | 86.8% | **76.8%** | 97.8% | 99.6% | 98.9% | 99.6% | 91.6% |
| twcert | 258 | 257 | 42 | 86.4% | 88.3% | 85.2% | 87.2% | 97.3% | **92.3%** | 100.0% | 97.7% | 99.6% | 99.6% | 99.6% |
| mongodb | 211 | 209 | 81 | 57.9% | 60.8% | 56.5% | 59.3% | 86.1% | **46.0%** | 91.9% | 96.2% | 96.2% | 98.1% | 99.5% |
| f5 | 182 | 182 | 57 | 57.1% | 54.4% | 66.5% | 63.7% | 77.5% | **76.4%** | 92.9% | 100.0% | 99.5% | 99.5% | 83.0% |
| AMZN | 188 | 181 | 75 | 43.6% | 44.2% | 41.4% | 42.5% | 75.1% | **43.6%** | 91.2% | 93.4% | 92.3% | 92.8% | 94.5% |
| cisa-cg | 175 | 171 | 88 | 62.6% | 59.1% | 60.2% | 56.7% | 87.7% | **59.6%** | 93.6% | 97.1% | 97.7% | 98.2% | 97.7% |
| ABB | 148 | 129 | 82 | 25.6% | 25.6% | 20.9% | 20.2% | 84.5% | **43.6%** | 95.3% | 99.2% | 91.5% | 93.0% | 91.5% |
| jpcert | 434 | 128 | 40 | 50.0% | 74.2% | 49.2% | 73.4% | 89.8% | **71.8%** | 100.0% | 96.1% | 100.0% | 100.0% | 100.0% |
| CERTVDE | 107 | 103 | 25 | 92.2% | 91.3% | 92.2% | 91.3% | 97.1% | **77.4%** | 98.1% | 100.0% | 100.0% | 100.0% | 100.0% |

## Source typing (data before 2026-01-01 only; FD_oos ≥ 90% means derived)

- **derived**: VulDB (93.0%)
- **independent**: VulnCheck (40.8%), siemens (77.1%), icscert (66.1%), intel (47.7%), juniper (51.7%), ABB (37.5%), twcert (83.3%)
- **v4_only**: GitHub_M (n=1529), INCIBE (n=369), CERT-PL (n=204), qnap (n=186), Liferay (n=145), palo_alto (n=103)

Share of each type among all v4 labels (typing above): derived 33.9%, independent 26.7%, v4_only 17.9%, untyped (small sources) 21.5%

Threshold sensitivity (sources typed as derived): ≥80%: VulDB, twcert; ≥90%: VulDB; ≥95%: none

## Quarterly exact-vector hit rate of rule R for the main sources

- siemens: 2024Q2 50% (n=48), 2024Q3 69% (n=78), 2024Q4 42% (n=79), 2025Q1 53% (n=45), 2025Q2 86% (n=127), 2025Q3 71% (n=55), 2025Q4 70% (n=46), 2026Q2 61% (n=31), 2026Q3 50% (n=40)
- VulDB: 2024Q2 75% (n=373), 2024Q3 80% (n=698), 2024Q4 80% (n=718), 2025Q1 93% (n=948), 2025Q2 100% (n=1891), 2025Q3 100% (n=1885), 2025Q4 100% (n=1175), 2026Q1 100% (n=1425), 2026Q2 100% (n=1894), 2026Q3 100% (n=1832)
- icscert: 2024Q3 68% (n=60), 2024Q4 86% (n=37), 2025Q1 63% (n=60), 2025Q2 73% (n=82), 2025Q3 68% (n=65), 2025Q4 58% (n=72), 2026Q1 93% (n=82), 2026Q2 68% (n=80), 2026Q3 79% (n=165)
- VulnCheck: 2025Q4 40% (n=235), 2026Q1 54% (n=1464), 2026Q2 67% (n=1643), 2026Q3 77% (n=2961)

## Labels that carry information beyond the v3.1 vector

- v4 labels in total 37,997; of these, v4 only (no same-source v3.1) 14,524; same-source pairs 23,473, of which identical to rule R 19,083 (81.3%)
- Labels that differ from R(v3.1) or have no v3.1 vector (upper bound of the labels that carry information beyond the v3.1 vector): 18,914 (49.8%)