#!/usr/bin/env bash
# W4 第二步：多种子主实验。每个（划分 × 种子）各跑"无辅助"和"有辅助"两个版本，配置来自 select_config.py。
# 用法（在项目根目录）：
#   NONE_ARGS="--epochs 5 --class_weight none" AUX_ARGS="--epochs 5 --class_weight none --aux_v31 --aux_lambda 0.5" \
#   SEEDS="0 1 2 3 4" bash scripts/run_w4_seeds.sh
# 支持中断后续跑（已有结果的运行会跳过）。跑完后：python src/aggregate_seeds.py --config_none ... --config_aux ... --lam ...
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
