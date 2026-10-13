#!/usr/bin/env bash
# CWE 辅助任务对照实验（T2 时间划分）：检验 v3.1 辅助任务的增益是否只因为多看了约 6 万条 CVE 描述、多了一个监督信号。
# 三组，输入都只用描述（--no_cwe_in_text。CWE 编号若在输入里，预测 CWE 类别就等于照抄输入，对照失去意义）：
#   ① 无辅助；② CWE 辅助（前 50 个 CWE + 其他，λ=0.5）；③ v3.1 辅助（λ=0.5）。
# ②③ 用完全相同的辅助样本（同一个池、同一个种子）；配置沿用 W4 选定的（5 轮、inv_sqrt 类别加权），各 3 个种子。
# 按种子轮流跑三组，中途停止时已完成的种子三组齐全。支持中断后续跑（--skip_existing）。
# 汇总：python src/cwe_control.py（CPU）
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
