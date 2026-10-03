"""第三轮审稿 M2（10-03，用户同意花 API 费用）：DeepSeek-V4-Pro 在同一批 2,000 条测试 CVE 上按主运行的设置
（AutoCVSS DTD 提示、零样本、关闭思考、接口默认采样）完整重复两遍，用来把大模型的采样随机性算进排名翻转的置信区间。
两遍依次运行；各自写到 results/autocvss_baseline/deepseek-v4-pro_DTD_s0_fullrep{1,2}/，中断后重跑会跳过已完成的调用。
本机网络不稳时请求会失败（连接错误、超时）；失败的请求不能当成"最保守标签"，所以每一遍都用 --retry_failed 反复补跑，
直到没有失败的请求（最多 8 轮）。密钥由 src/run_autocvss_baseline.py 从 .deepseek_key 读取，本脚本不接触密钥。
用法：.venv-llm/Scripts/python.exe scripts/run_llm_fullreps.py
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
