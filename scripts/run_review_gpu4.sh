#!/usr/bin/env bash
# GPU runs for configuration selection, step-matched baselines and timing sensitivity:
#   A. Configuration search (seed 0): each LOSO split searches again on its own validation set (auxiliary: λ in {0.5, 1.0} × class
#      weighting in {none, inv_sqrt}; baseline: class weighting × epoch cap in {5, 10}); on the temporal split, the baseline is added
#      with 10 epochs unweighted and 25 epochs (as many optimisation steps as the auxiliary model's 5 epochs).
#   B. Temporal split: seeds 1-2 for the baseline with 25 epochs (the step-matched baseline for the auxiliary model), seeds 3-4 for
#      10 epochs (the main table uses 5 seeds).
#   C. Temporal split without the CVEs updated after the cut-off (--exclude_ids): baseline 10 epochs and auxiliary 5 epochs, seeds 0-2.
#   D. Seeds 0-4 for the configuration selected on each split by src/select_loso_config.py (existing runs are skipped).
# Resumable after an interruption (--skip_existing). Summary: python src/select_loso_config.py; python src/review_gpu4_summary.py (CPU)
set -o pipefail
cd "$(dirname "$0")/.."
source /usr/local/miniconda3/bin/activate py312 2>/dev/null || true
export HF_ENDPOINT=${HF_ENDPOINT:-https://hf-mirror.com}
command -v python > /dev/null || { echo "!!!!! 找不到 python（需要先激活 py312 环境）"; exit 1; }
MODEL=${MODEL:-microsoft/deberta-v3-base}
mkdir -p results/encoder
LOG=results/encoder/log_review_gpu4_$(date +%Y%m%d_%H%M).txt
run () {
  echo "===== $(date '+%F %T') $* =====" | tee -a "$LOG"
  python src/train_encoder.py --model "$MODEL" --task T2 --source_mode none --skip_existing "$@" 2>&1 | tee -a "$LOG" \
    || echo "!!!!! 失败（已跳过，继续下一个）：$*" | tee -a "$LOG"
}

# A. 配置搜索（种子 0）
for SPLIT in loso:VulnCheck loso:GitHub_M loso:VulDB; do
  run --split "$SPLIT" --seed 0 --aux_v31 --aux_lambda 0.5 --class_weight none --epochs 5
  run --split "$SPLIT" --seed 0 --aux_v31 --aux_lambda 1.0 --class_weight inv_sqrt --epochs 5
  run --split "$SPLIT" --seed 0 --aux_v31 --aux_lambda 1.0 --class_weight none --epochs 5
  run --split "$SPLIT" --seed 0 --class_weight none --epochs 5
  run --split "$SPLIT" --seed 0 --class_weight none --epochs 10
done
run --split temporal --seed 0 --class_weight none --epochs 10
run --split temporal --seed 0 --class_weight inv_sqrt --epochs 25

# B. 步数相同的基线；10 轮补满 5 个种子
for SEED in 1 2; do run --split temporal --seed "$SEED" --class_weight inv_sqrt --epochs 25; done
for SEED in 3 4; do run --split temporal --seed "$SEED" --class_weight inv_sqrt --epochs 10; done

# C. 时间信息敏感性
for SEED in 0 1 2; do
  run --split temporal --seed "$SEED" --class_weight inv_sqrt --epochs 10 --exclude_ids data/processed/late_updated_ids.json
  run --split temporal --seed "$SEED" --aux_v31 --aux_lambda 0.5 --class_weight inv_sqrt --epochs 5 --exclude_ids data/processed/late_updated_ids.json
done

# D. 选中的配置跑满 5 个种子
python src/select_loso_config.py | tee -a "$LOG"
python src/select_loso_config.py --shell > /tmp/selected_configs.txt || { echo "!!!!! 配置选择失败" | tee -a "$LOG"; exit 1; }
while IFS='|' read -r SPLIT ARGS; do
  for SEED in 0 1 2 3 4; do
    # shellcheck disable=SC2086
    run --split "$SPLIT" --seed "$SEED" $ARGS
  done
done < /tmp/selected_configs.txt
echo "===== 全部完成 $(date '+%F %T') =====" | tee -a "$LOG"
