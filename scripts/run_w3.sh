#!/usr/bin/env bash
# W3 第一批 GPU 实验（计划 v2）：DeBERTa-v3-base，1 个随机种子。
#   主实验：T2（只有描述）× {时间划分, 留一 VulnCheck, 留一 GitHub_M, 留一 VulDB} × {基础, +v3.1 辅助任务（贡献 3）} = 8 次
#   对照：  T1 时间划分 × 基础 = 1 次
#   分析：  T2 时间划分 × {来源特征, 来源习惯矩阵} = 2 次（贡献 2' 已降级为分析，这两次只用于论文中的分析小节）
# 用法（在项目根目录）：bash scripts/run_w3.sh
# 换模型：MODEL=answerdotai/ModernBERT-base bash scripts/run_w3.sh；换种子：SEED=1 bash scripts/run_w3.sh
set -e
cd "$(dirname "$0")/.."
MODEL=${MODEL:-microsoft/deberta-v3-base}
SEED=${SEED:-0}
mkdir -p results/encoder
LOG=results/encoder/log_w3_$(date +%Y%m%d_%H%M).txt
run () { echo "===== $* =====" | tee -a "$LOG"; python src/train_encoder.py --model "$MODEL" --seed "$SEED" "$@" 2>&1 | tee -a "$LOG"; }

for SPLIT in temporal loso:VulnCheck loso:GitHub_M loso:VulDB; do
  run --task T2 --split "$SPLIT" --source_mode none
  run --task T2 --split "$SPLIT" --source_mode none --aux_v31
done
run --task T1 --split temporal --source_mode none
run --task T2 --split temporal --source_mode feature
run --task T2 --split temporal --source_mode crowd
echo "全部完成，日志：$LOG"
