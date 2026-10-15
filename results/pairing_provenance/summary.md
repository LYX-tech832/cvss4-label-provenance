# Pairing provenance (approximation of D4 of Vieira et al. 2026: published from 2023-11-01 to 2026-07-12, with both v3.1 and v4.0, 25,377 CVEs)

Top 5 sources of the v4.0 labels: cna@vuldb.com 11,254 (44.3%); disclosure@vulncheck.com 4,101 (16.2%); security-advisories@github.com 3,011 (11.9%); ics-cert@hq.dhs.gov 618 (2.4%); productcert@siemens.com 547 (2.2%)

| Setting | n | Of which VulDB | Rule-R band accuracy | Underestimation | Exact vector |
|---|---|---|---|---|---|
| cross-source (NVD v3.1 ↔ CNA v4.0), all available | 15,488 | 44.9% | 45.8% | 4.9% | 12.9% |
| same-source (CNA v3.1 ↔ CNA v4.0), all available | 18,218 | 61.8% | 96.2% | 0.4% | 81.1% |
| same-source, without VulDB | 6,964 | 0.0% | 90.2% | 1.1% | 57.0% |
| strict pairing · NVD's v3.1 | 8,470 | 82.1% | 30.7% | 1.1% | 5.4% |
| strict pairing · CNA's v3.1 | 8,470 | 82.1% | 98.0% | 0.4% | 86.5% |
| strict pairing without VulDB · NVD's v3.1 | 1,518 | 0.0% | 65.3% | 5.5% | 16.5% |
| strict pairing without VulDB · CNA's v3.1 | 1,518 | 0.0% | 89.2% | 2.0% | 52.2% |

On the 8,470 strictly paired CVEs, the NVD's and the CNA's v3.1 vectors are identical for 7.6%; per-metric agreement: AV 98.2%, AC 96.8%, PR 77.6%, UI 97.0%, S 85.5%, C 24.9%, I 38.4%, A 35.3%