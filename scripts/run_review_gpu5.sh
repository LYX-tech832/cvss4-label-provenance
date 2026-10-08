#!/usr/bin/env bash
# 第四轮审稿意见（10-03 晚）的 GPU 实验。用法：bash scripts/run_review_gpu5.sh [阶段…]（不带参数 = D0 A B C）
#   D0. M3 留一来源划分上步数相当的无辅助基线，先只跑种子 0（VulnCheck 16 轮、GitHub 15 轮、VulDB 18 轮；类别加权）。
#       轮数 = 5 ×（v4 训练样本 + 6 万辅助样本）/ v4 训练样本，与辅助模型 5 轮的优化步数相当（时间划分上对应的是已有的 25 轮）。
#       它作为无辅助模型的一个候选配置，和原有候选一起按各划分自己的验证集选（src/select_loso_config.py）。约 1.8 小时。
#   A.  M3 顺序微调基线（时间划分）：第一阶段只用 v3.1 池训练 v3.1 头并保存编码器（--v31_only --save_encoder，5 轮）；
#       第二阶段从这个编码器出发只用 v4 标签微调（--init_encoder；种子 0 跑 5 / 10 / 25 轮，按验证集选一个，再跑种子 1–2）。约 2.2–3 小时。
#   B.  M3 留一来源划分上的打乱标签对照（--aux_shuffle，配置同各划分选中的辅助模型：λ=1、类别加权、5 轮；种子 0–2）。约 5.3 小时。
#   C.  M4 最早的 5% v4 标签（--frac_mode earliest，种子 0–2）：辅助 5 轮；无辅助 50 轮（与随机 5% 的做法相同）。约 1.3 小时。
#   D1.（D0 之后按需）每个划分选中的配置跑满种子 0–4；只有 D0 的配置在某个划分被选中时才会有新的训练（每个划分 4 次、约 2.4 小时）。
# 时间按 RTX 4090 估计。支持中断后续跑（--skip_existing）。
set -o pipefail
cd "$(dirname "$0")/.."
source /usr/local/miniconda3/bin/activate py312 2>/dev/null || true
export HF_ENDPOINT=${HF_ENDPOINT:-https://hf-mirror.com}
command -v python > /dev/null || { echo "!!!!! 找不到 python（需要先激活 py312 环境）"; exit 1; }
MODEL=${MODEL:-microsoft/deberta-v3-base}
PHASES=${*:-D0 A B C}
mkdir -p results/encoder
LOG=results/encoder/log_review_gpu5_$(date +%Y%m%d_%H%M).txt
run () {
  echo "===== $(date '+%F %T') $* =====" | tee -a "$LOG"
  python src/train_encoder.py --model "$MODEL" --task T2 --source_mode none --skip_existing "$@" 2>&1 | tee -a "$LOG" \
    || echo "!!!!! 失败（已跳过，继续下一个）：$*" | tee -a "$LOG"
}
enc_path () { echo "results/encoder/T2_temporal_deberta-v3-base_none_v31only_e5_enc_s$1/encoder.pt"; }
seq_result () { echo "results/encoder/T2_temporal_deberta-v3-base_none_e$1_cwinv_sqrt_seq_s$2/results.json"; }
echo "===== 阶段：$PHASES =====" | tee -a "$LOG"

for PH in $PHASES; do
  echo "===== $(date '+%F %T') 阶段 $PH 开始 =====" | tee -a "$LOG"
  case "$PH" in
    D0)
      run --split loso:VulnCheck --seed 0 --class_weight inv_sqrt --epochs 16
      run --split loso:GitHub_M --seed 0 --class_weight inv_sqrt --epochs 15
      run --split loso:VulDB --seed 0 --class_weight inv_sqrt --epochs 18
      python src/select_loso_config.py | tee -a "$LOG" ;;
    A)
      # 种子 0：第一阶段 + 第二阶段三个轮数上限，按验证集选
      [ -f "$(seq_result 5 0)" ] && [ -f "$(seq_result 10 0)" ] && [ -f "$(seq_result 25 0)" ] \
        || run --split temporal --seed 0 --v31_only --epochs 5 --save_encoder
      for E in 5 10 25; do
        if [ -f "$(seq_result "$E" 0)" ] || [ -f "$(enc_path 0)" ]; then
          run --split temporal --seed 0 --init_encoder "$(enc_path 0)" --class_weight inv_sqrt --epochs "$E"
        else
          echo "!!!!! 第一阶段没有产出编码器权重：$(enc_path 0)" | tee -a "$LOG"
        fi
      done
      BEST=$(python -c "
import json
f = 'results/encoder/T2_temporal_deberta-v3-base_none_e{}_cwinv_sqrt_seq_s0/results.json'
v = {e: json.load(open(f.format(e), encoding='utf-8'))['val_best_mean_f1'] for e in (5, 10, 25)}
print(max(v, key=v.get))
print(v, file=__import__('sys').stderr)" 2>> "$LOG")
      if [ -z "$BEST" ]; then
        echo "!!!!! 顺序微调：种子 0 的三个配置没有跑全，无法选择" | tee -a "$LOG"
      else
        echo "顺序微调第二阶段按验证集选中的轮数上限：$BEST" | tee -a "$LOG"
        rm -f "$(enc_path 0)"  # 每个约 0.7 GB，用完即删
        for SEED in 1 2; do
          [ -f "$(seq_result "$BEST" "$SEED")" ] || run --split temporal --seed "$SEED" --v31_only --epochs 5 --save_encoder
          if [ -f "$(seq_result "$BEST" "$SEED")" ] || [ -f "$(enc_path "$SEED")" ]; then
            run --split temporal --seed "$SEED" --init_encoder "$(enc_path "$SEED")" --class_weight inv_sqrt --epochs "$BEST"
            [ -f "$(seq_result "$BEST" "$SEED")" ] && rm -f "$(enc_path "$SEED")"
          else
            echo "!!!!! 第一阶段没有产出编码器权重：$(enc_path "$SEED")" | tee -a "$LOG"
          fi
        done
      fi ;;
    B)
      for SEED in 0 1 2; do
        for SPLIT in loso:VulnCheck loso:GitHub_M loso:VulDB; do
          run --split "$SPLIT" --seed "$SEED" --aux_v31 --aux_shuffle --aux_lambda 1.0 --class_weight inv_sqrt --epochs 5
        done
      done ;;
    C)
      for SEED in 0 1 2; do
        run --split temporal --seed "$SEED" --aux_v31 --aux_lambda 0.5 --class_weight inv_sqrt --epochs 5 --train_frac 0.05 --frac_mode earliest
        run --split temporal --seed "$SEED" --class_weight inv_sqrt --epochs 50 --train_frac 0.05 --frac_mode earliest
      done ;;
    D1)
      python src/select_loso_config.py | tee -a "$LOG"
      python src/select_loso_config.py --shell > /tmp/selected_configs5.txt || { echo "!!!!! 配置选择失败" | tee -a "$LOG"; continue; }
      while IFS='|' read -r SPLIT ARGS; do
        for SEED in 0 1 2 3 4; do
          # shellcheck disable=SC2086
          run --split "$SPLIT" --seed "$SEED" $ARGS
        done
      done < /tmp/selected_configs5.txt ;;
    *) echo "!!!!! 未知阶段：$PH" | tee -a "$LOG" ;;
  esac
done
echo "===== 全部完成 $(date '+%F %T') =====" | tee -a "$LOG"
