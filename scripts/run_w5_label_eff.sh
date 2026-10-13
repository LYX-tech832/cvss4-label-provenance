#!/usr/bin/env bash
# W5：标签效率曲线（T2 时间划分）。只用 5% / 10% / 25% / 50% 的 v4 训练标签（验证集、测试集、辅助样本不变），
# 比较"无辅助"与"有 v3.1 辅助"两个版本，配置沿用 W4 按验证集选定的（inv_sqrt 类别加权；辅助 λ=0.5），各 3 个种子。
# 100% 的点直接用 W4 的运行结果。
# 无辅助版本的训练轮数按比例放大（上限 50 轮），使优化步数与全量数据训练 5 轮大致相当，避免小样本时欠训练；
# 有辅助版本每轮都包含约 6 万条辅助样本，步数已经足够，保持 5 轮。最佳轮次仍只按验证集选。
# 支持中断后续跑（--skip_existing）。
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
