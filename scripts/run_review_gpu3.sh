#!/usr/bin/env bash
# 第六份审稿意见 M5 的补充对照（用户 10-01 同意"加跑"）：
#   5% v4 训练标签 + 打乱 v3.1 标签的辅助任务（时间划分，5 轮、inv_sqrt、λ=0.5，种子 0–2），
#   用来检验要点第 4 条（5% 标签 + v3.1 辅助 ≈ 全部标签无辅助）靠的是 v3.1 信息还是样本池本身。
# 等 run_review_gpu2.sh 跑完再开始，避免两个训练抢同一块 GPU。支持中断后续跑（--skip_existing）。
# 汇总：python src/review_gpu2_summary.py（CPU）
set -o pipefail
cd "$(dirname "$0")/.."
while pgrep -f "run_review_gpu2[.]sh" > /dev/null; do sleep 60; done
MODEL=${MODEL:-microsoft/deberta-v3-base}
mkdir -p results/encoder
LOG=results/encoder/log_review_gpu3_$(date +%Y%m%d_%H%M).txt
run () {
  echo "===== $(date '+%F %T') $* =====" | tee -a "$LOG"
  python src/train_encoder.py --model "$MODEL" --task T2 --source_mode none --class_weight inv_sqrt --skip_existing "$@" 2>&1 | tee -a "$LOG" \
    || echo "!!!!! 失败（已跳过，继续下一个）：$*" | tee -a "$LOG"
}
for SEED in 0 1 2; do
  run --split temporal --seed "$SEED" --epochs 5 --aux_v31 --aux_lambda 0.5 --aux_shuffle --train_frac 0.05
done
echo "===== 全部完成 $(date '+%F %T') =====" | tee -a "$LOG"
