#!/usr/bin/env bash
# CWE auxiliary-task control (T2 temporal split): is the gain of the v3.1 auxiliary task only due to seeing about 60,000 more CVE
# descriptions and one more supervision signal?
# Three groups, all with the description only as input (--no_cwe_in_text; if the CWE identifier were in the input, predicting the CWE
# class would amount to copying the input, and the control would be meaningless):
#   (1) no auxiliary task; (2) CWE auxiliary task (top 50 CWEs + other, λ=0.5); (3) v3.1 auxiliary task (λ=0.5).
# (2) and (3) use exactly the same auxiliary samples (same pool, same seed); configuration as selected in W4 (5 epochs, inv_sqrt class
# weighting), 3 seeds each.
# The three groups are run seed by seed, so that all three are complete for every finished seed if the batch stops early.
# Resumable after an interruption (--skip_existing).
# Summary: python src/cwe_control.py (CPU)
set -o pipefail
cd "$(dirname "$0")/.."
MODEL=${MODEL:-microsoft/deberta-v3-base}
SEEDS=${SEEDS:-"0 1 2"}
mkdir -p results/encoder
LOG=results/encoder/log_cwe_control_$(date +%Y%m%d_%H%M).txt
run () {
  echo "===== $(date '+%F %T') $* =====" | tee -a "$LOG"
  python src/train_encoder.py --model "$MODEL" --task T2 --split temporal --source_mode none --epochs 5 --class_weight inv_sqrt \
    --no_cwe_in_text --skip_existing "$@" 2>&1 | tee -a "$LOG" \
    || echo "!!!!! 失败（已跳过，继续下一个）：$*" | tee -a "$LOG"
}
for SEED in $SEEDS; do
  run --seed "$SEED"
  run --seed "$SEED" --aux_cwe --aux_lambda 0.5
  run --seed "$SEED" --aux_v31 --aux_lambda 0.5
done
echo "===== CWE 对照全部完成 $(date '+%F %T') =====" | tee -a "$LOG"
