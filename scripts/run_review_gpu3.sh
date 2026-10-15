#!/usr/bin/env bash
# Further shuffled-label control:
#   5% of the v4 training labels + an auxiliary task with shuffled v3.1 labels (temporal split, 5 epochs, inv_sqrt, λ=0.5, seeds 0-2),
#   to test whether the result "5% of the labels + v3.1 auxiliary task ≈ all labels without it" relies on the v3.1 information or on
#   the sample pool itself.
# Starts after run_review_gpu2.sh has finished, so that two trainings do not compete for the same GPU. Resumable after an interruption
# (--skip_existing).
# Summary: python src/review_gpu2_summary.py (CPU)
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
