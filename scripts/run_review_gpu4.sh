#!/usr/bin/env bash
# 第二轮审稿意见（SCI第二轮审稿报告.md，10-02）的 GPU 实验（用户 10-02 同意 P1、P2、P4）：
#   A. P1/P4 配置搜索（种子 0）：每个 LOSO 划分在自己的验证集上重新搜索（辅助：λ ∈ {0.5, 1.0} × 类别加权 ∈ {无, inv_sqrt}；
#      无辅助：类别加权 × 轮数上限 ∈ {5, 10}）；时间划分补无辅助的 10 轮无加权与 25 轮（与辅助模型 5 轮的优化步数相当）。
#   B. P4：时间划分无辅助 25 轮补种子 1–2（与辅助模型比较步数相同的基线），10 轮补种子 3–4（主表用 5 个种子）。
#   C. P2：时间划分去掉截止日期后更新过的 CVE（--exclude_ids），无辅助 10 轮与辅助 5 轮，种子 0–2。
#   D. 按 src/select_loso_config.py 的选择结果，每个划分选中的配置跑满种子 0–4（已有的自动跳过）。
# 支持中断后续跑（--skip_existing）。汇总：python src/select_loso_config.py；python src/review_gpu4_summary.py（CPU）
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
