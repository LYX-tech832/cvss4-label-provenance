#!/usr/bin/env bash
# 第六份审稿意见（SCI审稿报告.md，10-01）M5 的两项 GPU 实验（用户 10-01 同意）：
#   1. 打乱 v3.1 标签的负对照：时间划分，W4 选定配置（5 轮、inv_sqrt、λ=0.5），--aux_v31 --aux_shuffle，种子 0–2；
#   2. 三个 LOSO 划分的无辅助基线训练 10 轮（时间划分上已表明 5 轮不够，而辅助模型 10 轮不变），先种子 0–2，再 3–4。
# 支持中断后续跑（--skip_existing）。汇总：python src/review_gpu2_summary.py（CPU）
set -o pipefail
cd "$(dirname "$0")/.."
MODEL=${MODEL:-microsoft/deberta-v3-base}
mkdir -p results/encoder
LOG=results/encoder/log_review_gpu2_$(date +%Y%m%d_%H%M).txt
run () {
  echo "===== $(date '+%F %T') $* =====" | tee -a "$LOG"
  python src/train_encoder.py --model "$MODEL" --task T2 --source_mode none --class_weight inv_sqrt --skip_existing "$@" 2>&1 | tee -a "$LOG" \
    || echo "!!!!! 失败（已跳过，继续下一个）：$*" | tee -a "$LOG"
}
for SEED in 0 1 2; do
  run --split temporal --seed "$SEED" --epochs 5 --aux_v31 --aux_lambda 0.5 --aux_shuffle
done
for SEEDS in "0 1 2" "3 4"; do
  for SEED in $SEEDS; do
    for SPLIT in loso:VulnCheck loso:GitHub_M loso:VulDB; do
      run --split "$SPLIT" --seed "$SEED" --epochs 10
    done
  done
done
echo "===== 全部完成 $(date '+%F %T') =====" | tee -a "$LOG"
