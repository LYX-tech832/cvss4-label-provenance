#!/usr/bin/env bash
# Additional GPU runs (T2 temporal split, 3 seeds each):
#   1. Training epochs: baseline / v3.1 auxiliary task trained for 10 epochs (otherwise as the configuration selected in W4: inv_sqrt
#      class weighting, λ=0.5), to check whether 5 epochs are too few;
#   2. Pseudo-label control (--pseudo_v4): the same 60,000 auxiliary samples as the v3.1 auxiliary task, with their v3.1 vectors converted
#      by rule R into v4 pseudo-labels that supervise the v4 heads directly, weight λ=0.5, 5 epochs;
#   3. DeBERTa pipeline (--v31_only): the v3.1 heads trained only on the same 60,000 auxiliary samples, predictions converted to v4 with
#      rule R, no v4 training labels, 5 epochs.
# Usage: bash scripts/run_review_gpu.sh [A|B|all]
#   A = the v3.1 auxiliary run of item 1 (slowest, about 3 hours); B = the rest (about 3.4 hours); all = everything in turn.
#   With enough GPU memory, A and B can run in two terminals (a 24 GB card holds two DeBERTa-base processes).
# Resumable after an interruption (--skip_existing). Summary: python src/review_gpu_summary.py (CPU)
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
