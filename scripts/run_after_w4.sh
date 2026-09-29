#!/usr/bin/env bash
# 等 W4 批次结束后，自动依次执行：① W5 标签效率曲线；② 本地开源大模型（Qwen3-8B）基线。
# 用法（在项目根目录）：W4_PID=<W4 的进程号> setsid nohup bash scripts/run_after_w4.sh > after_w4.out 2>&1 < /dev/null &
set -o pipefail
cd "$(dirname "$0")/.."
: "${W4_PID:?需要设置 W4_PID}"
echo "等待 W4（PID $W4_PID）结束…… $(date '+%F %T')"
while kill -0 "$W4_PID" 2>/dev/null; do sleep 60; done
echo "W4 已结束 $(date '+%F %T')"
grep -q "全部完成" w4.out || echo "!!!!! 注意：w4.out 里没有'全部完成'，W4 可能没有正常结束"
if [ -f src/train_encoder.py.w5 ]; then  # 换上支持 --train_frac 的训练脚本（W4 运行期间不改动它正在用的文件）
  cp src/train_encoder.py src/train_encoder.py.w4bak && mv src/train_encoder.py.w5 src/train_encoder.py
fi
source /usr/local/miniconda3/bin/activate py312
export HF_ENDPOINT=https://hf-mirror.com
bash scripts/run_w5_label_eff.sh
bash scripts/run_llm_local.sh
echo "===== run_after_w4 全部完成 $(date '+%F %T') ====="
