#!/usr/bin/env bash
# 回应审稿意见的 GPU 实验（T2 时间划分，各 3 个种子；9-30 用户选定第 1–3 项）：
#   1. 训练轮数：无辅助 / v3.1 辅助各训练 10 轮（其余与 W4 选定配置相同：inv_sqrt 类别加权、λ=0.5），检验 5 轮是否训练不足；
#   2. 伪标签对照（--pseudo_v4）：与 v3.1 辅助完全相同的 60,000 条辅助样本，v3.1 向量按规则 R 换算成 v4 伪标签直接监督 v4 头，权重 λ=0.5，5 轮；
#   3. DeBERTa 版流水线（--v31_only）：只用同样的 60,000 条辅助样本训练 v3.1 头，预测后按规则 R 换算成 v4，不用任何 v4 训练标签，5 轮。
# 用法：bash scripts/run_review_gpu.sh [A|B|all]
#   A = 第 1 项中的 v3.1 辅助（最慢，约 3 小时）；B = 其余（约 3.4 小时）；all = 依次全部。
#   显存够时可以开两个终端分别跑 A 和 B（24 GB 的卡可以同时容纳两个 DeBERTa-base 进程）。
# 支持中断后续跑（--skip_existing）。汇总：python src/review_gpu_summary.py（CPU）
set -o pipefail
cd "$(dirname "$0")/.."
MODEL=${MODEL:-microsoft/deberta-v3-base}
SEEDS=${SEEDS:-"0 1 2"}
QUEUE=${1:-all}
mkdir -p results/encoder
LOG=results/encoder/log_review_gpu_${QUEUE}_$(date +%Y%m%d_%H%M).txt
run () {
  echo "===== $(date '+%F %T') $* =====" | tee -a "$LOG"
  python src/train_encoder.py --model "$MODEL" --task T2 --split temporal --source_mode none --skip_existing "$@" 2>&1 | tee -a "$LOG" \
    || echo "!!!!! 失败（已跳过，继续下一个）：$*" | tee -a "$LOG"
}
for SEED in $SEEDS; do
  if [ "$QUEUE" = "B" ] || [ "$QUEUE" = "all" ]; then
    run --seed "$SEED" --epochs 5 --class_weight inv_sqrt --pseudo_v4 --aux_lambda 0.5
    run --seed "$SEED" --epochs 5 --v31_only
    run --seed "$SEED" --epochs 10 --class_weight inv_sqrt
  fi
  if [ "$QUEUE" = "A" ] || [ "$QUEUE" = "all" ]; then
    run --seed "$SEED" --epochs 10 --class_weight inv_sqrt --aux_v31 --aux_lambda 0.5
  fi
done
echo "===== 队列 $QUEUE 全部完成 $(date '+%F %T') =====" | tee -a "$LOG"
