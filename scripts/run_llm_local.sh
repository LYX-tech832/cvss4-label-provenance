#!/usr/bin/env bash
# 本地开源大模型基线：vLLM 部署 Qwen3-8B（关闭思考），在与 DeepSeek 相同的 2,000 条 CVE 上跑 AutoCVSS 零样本流程
# （DTD 提示；采样参数用服务端默认值，与 DeepSeek 主实验"不设温度"的做法一致）。
# 先做冒烟测试（3 条），通过后再跑全量；全量最多 3 小时。结束后关闭 vLLM，释放显存。
# 前提：已运行 scripts/setup_llm_env.sh。
set -o pipefail
cd "$(dirname "$0")/.."
export PATH=/root/venv-vllm/bin:/usr/local/cuda/bin:$PATH  # flashinfer 等组件现场编译需要 ninja 与 nvcc（9-27 首次运行就因找不到 ninja 失败）
export CUDA_HOME=/usr/local/cuda
export VLLM_USE_FLASHINFER_SAMPLER=0  # 改用 vLLM 自带的 PyTorch 采样实现，不需要现场编译；采样参数与分布不变
MODEL_DIR=${MODEL_DIR:-/root/models/Qwen3-8B}
PORT=${PORT:-8000}
OUT=results/autocvss_baseline
mkdir -p "$OUT"
/root/venv-vllm/bin/vllm serve "$MODEL_DIR" --served-model-name Qwen3-8B --port "$PORT" \
  --max-model-len 4096 --gpu-memory-utilization 0.90 > "$OUT/vllm_server.log" 2>&1 &
VLLM_PID=$!
for i in $(seq 1 90); do curl -sf "localhost:$PORT/v1/models" > /dev/null && break; sleep 10; done
if ! curl -sf "localhost:$PORT/v1/models" > /dev/null; then
  echo "!!!!! vLLM 没有启动成功，见 $OUT/vllm_server.log"; kill "$VLLM_PID" 2>/dev/null; exit 1
fi
echo "vLLM 已启动 $(date '+%F %T')"
ARGS=(--base_url "http://localhost:$PORT/v1" --model Qwen3-8B --mode json --thinking disabled --thinking_style qwen --workers 32)
CLIENT=/root/venv-llmclient/bin/python
if $CLIENT src/run_autocvss_baseline.py "${ARGS[@]}" --smoke_test > "$OUT/qwen3_smoke.log" 2>&1; then
  echo "冒烟测试通过，开始全量 $(date '+%F %T')"
  timeout 3h $CLIENT src/run_autocvss_baseline.py "${ARGS[@]}" > "$OUT/qwen3_full2000.log" 2>&1 \
    || echo "!!!!! Qwen3 全量运行失败或超时，见 $OUT/qwen3_full2000.log"
else
  echo "!!!!! Qwen3 冒烟测试失败，见 $OUT/qwen3_smoke.log"
fi
kill "$VLLM_PID" 2>/dev/null; wait "$VLLM_PID" 2>/dev/null
echo "===== 开源大模型基线结束 $(date '+%F %T') ====="
