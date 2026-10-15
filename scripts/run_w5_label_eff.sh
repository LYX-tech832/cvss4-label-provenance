#!/usr/bin/env bash
# W5: label-efficiency curves (T2 temporal split). Only 5% / 10% / 25% / 50% of the v4 training labels (validation set, test set and
# auxiliary samples unchanged), comparing the baseline with the v3.1 auxiliary variant; configuration as selected in W4 on the validation
# set (inv_sqrt class weighting; auxiliary λ=0.5), 3 seeds each. The 100% point uses the W4 runs.
# The number of epochs of the baseline is scaled up with the fraction (at most 50), so that the optimisation steps roughly match 5 epochs
# on the full data and small samples are not undertrained; the auxiliary variant already sees about 60,000 auxiliary samples per epoch
# and keeps 5 epochs. The best epoch is still selected on the validation set only.
# Resumable after an interruption (--skip_existing).
set -o pipefail
cd "$(dirname "$0")/.."
MODEL=${MODEL:-microsoft/deberta-v3-base}
SEEDS=${SEEDS:-"0 1 2"}
FRACS=${FRACS:-"0.05 0.1 0.25 0.5"}
mkdir -p results/encoder
LOG=results/encoder/log_w5_label_eff_$(date +%Y%m%d_%H%M).txt
run () {
  echo "===== $(date '+%F %T') $* =====" | tee -a "$LOG"
  python src/train_encoder.py --model "$MODEL" --task T2 --split temporal --source_mode none --class_weight inv_sqrt --skip_existing "$@" 2>&1 | tee -a "$LOG" \
    || echo "!!!!! 失败（已跳过，继续下一个）：$*" | tee -a "$LOG"
}
for SEED in $SEEDS; do
  for F in $FRACS; do
    E=$(python -c "print(min(50, round(5 / $F)))")
    run --seed "$SEED" --train_frac "$F" --epochs "$E"
    run --seed "$SEED" --train_frac "$F" --epochs 5 --aux_v31 --aux_lambda 0.5
  done
done
echo "===== W5 全部完成 $(date '+%F %T') =====" | tee -a "$LOG"
