"""CVEs to exclude in the sensitivity analysis of the information available at the temporal cut-off (CPU, reads the raw snapshot,
about 5 minutes).

The training data of the temporal split (v4.0 training and validation samples, v3.1 auxiliary pool) all come from the final snapshot of
2026-09-25. The CVE List keeps no history of its fields, but each container has providerMetadata.dateUpdated, which any change of the
container (description, CWE, vectors) updates. This script lists the CVEs published before 2026 whose CNA container or any ADP container
was updated on or after the cut-off (2026-01-01): their description, CWE or labels may have been written after the cut-off (an upper
bound, since any change counts).
Output: data/processed/late_updated_ids.json ({"v4": [...], "pool": [...], "counts": {...}}), used by train_encoder.py --exclude_ids.
"""

import json
import sys
import zipfile
from pathlib import Path

import orjson
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from baselines_v0 import CUTOFF, load  # noqa: E402
from pilot_transfer import v31_pool  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "processed" / "late_updated_ids.json"


def container_dates(ids):
    """每个 CVE：CNA 容器与各 ADP 容器 dateUpdated 中最晚的一个（任何一个在截止日期后更新都算）。"""
    want = set(ids)
    cna, latest = {}, {}
    with zipfile.ZipFile(ROOT / "data" / "raw" / "cves.zip") as z:
        for n in z.namelist():
            base = n.rsplit("/", 1)[-1][:-5] if n.endswith(".json") else None
            if base not in want:
                continue
            c = (orjson.loads(z.read(n)).get("containers") or {})
            dates = [((c.get("cna") or {}).get("providerMetadata") or {}).get("dateUpdated")]
            cna[base] = dates[0]
            dates += [(a.get("providerMetadata") or {}).get("dateUpdated") for a in (c.get("adp") or [])]
            latest[base] = max((d for d in dates if d), default=None)
    to_dt = lambda d: pd.to_datetime(pd.Series(d), utc=True, errors="coerce", format="mixed")  # noqa: E731
    return to_dt(cna), to_dt(latest)


def main():
    df = load()
    v4_pre = df.loc[df["pub"] < CUTOFF, "cve_id"]
    pool = v31_pool()["cve_id"]
    cna, latest = container_dates(set(v4_pre) | set(pool))
    late_cna = set(cna[cna >= CUTOFF].index)
    late_any = set(latest[latest >= CUTOFF].index)
    res = {"v4": sorted(set(v4_pre) & late_any), "pool": sorted(set(pool) & late_any),
           "counts": {"v4_before_2026": int(len(v4_pre)), "v4_cna_late": len(set(v4_pre) & late_cna), "v4_any_late": len(set(v4_pre) & late_any),
                      "pool_before_2026": int(len(pool)), "pool_cna_late": len(set(pool) & late_cna), "pool_any_late": len(set(pool) & late_any),
                      "missing_dates": int(latest.isna().sum())}}
    OUT.write_text(json.dumps(res), encoding="utf-8")
    print(json.dumps(res["counts"], indent=1))


if __name__ == "__main__":
    main()
