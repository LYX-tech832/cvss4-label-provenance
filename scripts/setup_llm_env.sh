#!/usr/bin/env bash
# Prepares the environment for the local open-weight LLM baseline on the GPU server. Uses only network and disk, not the GPU, so it can
# run while W4 is running.
#   /root/venv-vllm        vLLM inference server (separate environment, does not affect py312 used for training)
#   /root/venv-llmclient   client for the AutoCVSS driver script (inherits pandas etc. from py312; adds instructor / openai / langfuse<3)
#   /root/models/Qwen3-8B  model weights (downloaded through hf-mirror; Apache-2.0 licence)
# Usage (from the project root): setsid nohup bash scripts/setup_llm_env.sh > setup_llm.out 2>&1 < /dev/null &
set -e
PY=/usr/local/miniconda3/envs/py312/bin/python
export HF_ENDPOINT=https://hf-mirror.com
export HF_HUB_DISABLE_XET=1  # 新版 huggingface_hub 默认走 Xet 存储后端，它不经过 hf-mirror，直连会返回 401
[ -x /root/venv-vllm/bin/python ] || $PY -m venv /root/venv-vllm
/root/venv-vllm/bin/pip install -q vllm
[ -x /root/venv-llmclient/bin/python ] || $PY -m venv --system-site-packages /root/venv-llmclient
/root/venv-llmclient/bin/pip install -q instructor openai "langfuse>=2.59.3,<3"
/root/venv-vllm/bin/python - <<'EOF'
from huggingface_hub import snapshot_download
p = snapshot_download("Qwen/Qwen3-8B", local_dir="/root/models/Qwen3-8B",
                      allow_patterns=["*.json", "*.safetensors", "*.txt", "*.model", "tokenizer*", "LICENSE*"])
print("模型已下载到", p)
EOF
/root/venv-vllm/bin/python -c "import vllm, torch; print('vllm', vllm.__version__, 'torch', torch.__version__)"
/root/venv-llmclient/bin/python -c "import instructor, openai, langfuse, pandas; print('客户端环境正常：instructor', instructor.__version__, 'openai', openai.__version__)"
du -sh /root/venv-vllm /root/venv-llmclient /root/models/Qwen3-8B
echo "===== 环境准备完成 $(date '+%F %T') ====="
