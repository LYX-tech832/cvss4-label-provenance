#!/usr/bin/env bash
# W4 第一步：在验证集上调参（T2 时间划分，种子 0，统一训练 5 轮，按验证集选最佳轮次）。
#   无辅助：类别加权 {无, inv_sqrt}                 → 2 次
#   有辅助：λ {0.5, 1.0} × 类别加权 {无, inv_sqrt}    → 4 次
# 跑完后运行：python src/select_config.py   （只看验证集，为两个版本各选一个配置）
# 支持中断后续跑（已有结果的运行会跳过）。
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
