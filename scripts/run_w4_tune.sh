#!/usr/bin/env bash
# W4, step 1: tuning on the validation set (T2 temporal split, seed 0, always 5 epochs, best epoch selected on the validation set).
#   baseline:  class weighting {none, inv_sqrt}                  -> 2 runs
#   auxiliary: λ {0.5, 1.0} × class weighting {none, inv_sqrt}   -> 4 runs
# Afterwards run: python src/select_config.py   (validation set only; one configuration per variant)
# Resumable after an interruption (runs with results are skipped).
set -e
cd "$(dirname "$0")/.."
MODEL=${MODEL:-microsoft/deberta-v3-base}
mkdir -p results/encoder
LOG=results/encoder/log_w4_tune_$(date +%Y%m%d_%H%M).txt
run () { echo "===== $* =====" | tee -a "$LOG"; python src/train_encoder.py --model "$MODEL" --seed 0 --task T2 --split temporal --epochs 5 --skip_existing "$@" 2>&1 | tee -a "$LOG"; }

for CW in none inv_sqrt; do
  run --source_mode none --class_weight "$CW"
done
for LAM in 0.5 1.0; do
  for CW in none inv_sqrt; do
    run --source_mode none --aux_v31 --aux_lambda "$LAM" --class_weight "$CW"
  done
done
echo "全部完成，日志：$LOG"
