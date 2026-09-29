# Data notices

## CVE List

`data/processed/cve_records.parquet`, `data/cve_ids_v4.csv` and `data/cve_ids_v31_pool.csv` are derived from the CVE List (release `2026-09-25_all_CVEs_at_midnight` of <https://github.com/CVEProject/cvelistV5>).

Copyright © 1999-2026, The MITRE Corporation.

CVE Usage: MITRE hereby grants you a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license to reproduce, prepare derivative works of, publicly display, publicly perform, sublicense, and distribute Common Vulnerabilities and Exposures (CVE™). Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy.

(Terms of Use: <https://www.cve.org/Legal/TermsOfUse>, accessed 29 September 2026.)

## National Vulnerability Database

`probe/nvd_v4_records.jsonl` was retrieved from the NVD API (<https://nvd.nist.gov>) on 25 September 2026. This product uses data from the NVD API but is not endorsed or certified by the NVD.

## LLM answers

`results/autocvss_baseline/*/raw.jsonl` contain the answers of DeepSeek-V4-Pro (accessed through the DeepSeek API on 26 September 2026) and of the open-weight Qwen3-8B to the requests issued by AutoCVSS.
