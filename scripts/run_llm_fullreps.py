"""Repeated runs for the LLM's sampling randomness: DeepSeek-V4-Pro repeats the main run on the same 2,000 test CVEs twice in full, with
the settings of the main run (AutoCVSS DTD prompt, zero-shot, thinking disabled, default API sampling), so that the sampling randomness
can be included in the confidence intervals of the ranking reversal.
The two runs are made one after the other; each writes to results/autocvss_baseline/deepseek-v4-pro_DTD_s0_fullrep{1,2}/, and a rerun
after an interruption skips the finished requests. Requests fail when the local network is unstable (connection errors, timeouts);
failed requests must not be treated as the most conservative label, so each run is repeated with --retry_failed until no request has
failed (at most 8 rounds). The key is read by src/run_autocvss_baseline.py; this script does not touch it.
Usage: .venv-llm/Scripts/python.exe scripts/run_llm_fullreps.py
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "autocvss_baseline"
env = {k: v for k, v in os.environ.items() if k not in ("OPENAI_API_KEY", "OPENAI_BASE_URL")}
env["PYTHONIOENCODING"] = "utf-8"


def n_failed(rep):
    f = OUT / f"deepseek-v4-pro_DTD_s0_fullrep{rep}" / "results.json"
    return json.loads(f.read_text(encoding="utf-8")).get("n_failed_requests") if f.exists() else None


for rep in (1, 2):
    for attempt in range(1, 9):
        with open(OUT / f"fullrep{rep}.log", "a", encoding="utf-8") as f:
            f.write(f"\n===== fullrep{rep} 第 {attempt} 轮 {time.strftime('%F %T')} =====\n")
            f.flush()
            rc = subprocess.call([sys.executable, str(ROOT / "src" / "run_autocvss_baseline.py"), "--base_url", "https://api.deepseek.com",
                                  "--model", "deepseek-v4-pro", "--mode", "json", "--workers", "16", "--run_tag", f"fullrep{rep}", "--retry_failed"],
                                 cwd=ROOT, env=env, stdout=f, stderr=subprocess.STDOUT)
        nf = n_failed(rep)
        print(f"fullrep{rep} attempt {attempt}: exit code {rc}, failed requests {nf}", flush=True)
        if rc == 0 and nf == 0:
            break
        time.sleep(30)
    else:
        print(f"fullrep{rep}: STILL FAILING after 8 attempts", flush=True)
        sys.exit(1)
print("ALL DONE", flush=True)
