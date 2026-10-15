#!/usr/bin/env bash
# W4, step 2: multi-seed main runs. For each (split × seed), runs the baseline and the auxiliary variant, with configurations from select_config.py.
# Usage (from the project root):
#   NONE_ARGS="--epochs 5 --class_weight none" AUX_ARGS="--epochs 5 --class_weight none --aux_v31 --aux_lambda 0.5" \
#   SEEDS="0 1 2 3 4" bash scripts/run_w4_seeds.sh
# Resumable after an interruption (runs with results are skipped). Afterwards: python src/aggregate_seeds.py --config_none ... --config_aux ... --lam ...
set -e
cd "$(dirname "$0")/.."
: "${NONE_ARGS:?需要设置 NONE_ARGS}"
: "${AUX_ARGS:?需要设置 AUX_ARGS}"
MODEL=${MODEL:-microsoft/deberta-v3-base}
SEEDS=${SEEDS:-"0 1 2 3 4"}
SPLITS=${SPLITS:-"temporal loso:VulnCheck loso:GitHub_M loso:VulDB"}
mkdir -p results/encoder
LOG=results/encoder/log_w4_seeds_$(date +%Y%m%d_%H%M).txt
run () { echo "===== $* =====" | tee -a "$LOG"; python src/train_encoder.py --model "$MODEL" --task T2 --source_mode none --skip_existing "$@" 2>&1 | tee -a "$LOG"; }

for SEED in $SEEDS; do
  for SPLIT in $SPLITS; do
    # shellcheck disable=SC2086
    run --split "$SPLIT" --seed "$SEED" $NONE_ARGS
    # shellcheck disable=SC2086
    run --split "$SPLIT" --seed "$SEED" $AUX_ARGS
  done
done
echo "全部完成，日志：$LOG"
