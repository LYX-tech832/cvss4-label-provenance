#!/usr/bin/env bash
# W4 batch, fully automatic (unattended): (1) tuning (validation set only) -> (2) automatic configuration selection -> (3) 5 seeds × 4 splits × 2 variants.
# - A failed run does not stop the batch: it is logged and the next run starts
# - Finished runs are skipped (--skip_existing); rerun this script to resume after an interruption
# - Divergent training (loss NaN for 20 consecutive steps) stops that run (built into train_encoder.py)
# Usage (from the project root): setsid nohup bash scripts/run_w4_all.sh > w4.out 2>&1 < /dev/null &
set -o pipefail
cd "$(dirname "$0")/.."
MODEL=${MODEL:-microsoft/deberta-v3-base}
SEEDS=${SEEDS:-"0 1 2 3 4"}
SPLITS=${SPLITS:-"temporal loso:VulnCheck loso:GitHub_M loso:VulDB"}
mkdir -p results/encoder
LOG=results/encoder/log_w4_all_$(date +%Y%m%d_%H%M).txt
run () {
  echo "===== $(date '+%F %T') $* =====" | tee -a "$LOG"
  python src/train_encoder.py --model "$MODEL" --task T2 --source_mode none --skip_existing "$@" 2>&1 | tee -a "$LOG" \
    || echo "!!!!! 失败（已跳过，继续下一个）：$*" | tee -a "$LOG"
}

echo "===== ① 调参 =====" | tee -a "$LOG"
for CW in none inv_sqrt; do
  run --split temporal --seed 0 --epochs 5 --class_weight "$CW"
done
for LAM in 0.5 1.0; do
  for CW in none inv_sqrt; do
    run --split temporal --seed 0 --epochs 5 --aux_v31 --aux_lambda "$LAM" --class_weight "$CW"
  done
done

echo "===== ② 选配置（只看验证集） =====" | tee -a "$LOG"
python src/select_config.py 2>&1 | tee -a "$LOG"
NONE_ARGS=$(python -c "import json; print(json.load(open('results/encoder/selected_config.json'))['none']['args'])") || NONE_ARGS="--epochs 5 --class_weight none"
AUX_ARGS=$(python -c "import json; print(json.load(open('results/encoder/selected_config.json'))['aux']['args'])") || AUX_ARGS="--epochs 5 --class_weight none --aux_v31 --aux_lambda 0.5"
echo "选定：NONE_ARGS=[$NONE_ARGS]  AUX_ARGS=[$AUX_ARGS]" | tee -a "$LOG"

echo "===== ③ 多种子主实验 =====" | tee -a "$LOG"
for SEED in $SEEDS; do
  for SPLIT in $SPLITS; do
    # shellcheck disable=SC2086
    run --split "$SPLIT" --seed "$SEED" $NONE_ARGS
    # shellcheck disable=SC2086
    run --split "$SPLIT" --seed "$SEED" $AUX_ARGS
  done
done
echo "===== 全部完成 $(date '+%F %T') =====" | tee -a "$LOG"
