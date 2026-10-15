#!/usr/bin/env bash
# Two additional GPU experiments:
#   1. Negative control with shuffled v3.1 labels: temporal split, configuration selected in W4 (5 epochs, inv_sqrt, λ=0.5),
#      --aux_v31 --aux_shuffle, seeds 0-2;
#   2. The baseline trained for 10 epochs on the three LOSO splits (on the temporal split, 5 epochs proved too few for the baseline,
#      while the auxiliary model stays at 10 epochs), seeds 0-2 first, then 3-4.
# Resumable after an interruption (--skip_existing). Summary: python src/review_gpu2_summary.py (CPU)
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
