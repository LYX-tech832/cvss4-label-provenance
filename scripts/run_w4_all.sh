#!/usr/bin/env bash
# W4 全自动批次（无人值守）：① 调参（只看验证集）→ ② 自动选配置 → ③ 5 个种子 × 4 种划分 × 2 个版本。
# - 单个任务失败不会中断整批：记录到日志后继续下一个
# - 已完成的任务会跳过（--skip_existing），中断后重新执行本脚本即可续跑
# - 训练发散（loss 连续 20 步 NaN）会自动终止该任务（train_encoder.py 内置）
# 用法（在项目根目录）：setsid nohup bash scripts/run_w4_all.sh > w4.out 2>&1 < /dev/null &
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
