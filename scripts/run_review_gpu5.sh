#!/usr/bin/env bash
# Additional GPU runs (step-matched baselines on the leave-one-source-out splits, sequential fine-tuning, shuffled-label control,
# earliest 5% of the labels). Usage: bash scripts/run_review_gpu5.sh [stage...] (no argument = D0 A B C)
#   D0. Step-matched baselines on the leave-one-source-out splits, seed 0 first (VulnCheck 16 epochs, GitHub 15, VulDB 18; class-weighted).
#       Epochs = 5 × (v4 training samples + 60,000 auxiliary samples) / v4 training samples, as many optimisation steps as the auxiliary
#       model's 5 epochs (on the temporal split this is the existing 25 epochs). It is one more candidate configuration of the baseline
#       and is selected together with the other candidates on each split's own validation set (src/select_loso_config.py). About 1.8 hours.
#   A.  Sequential fine-tuning baseline (temporal split): stage 1 trains the v3.1 heads on the v3.1 pool only and saves the encoder
#       (--v31_only --save_encoder, 5 epochs); stage 2 fine-tunes from this encoder on the v4 labels only (--init_encoder; seed 0 with
#       5 / 10 / 25 epochs, one selected on the validation set, then seeds 1-2). About 2.2-3 hours.
#   B.  Shuffled-label control on the leave-one-source-out splits (--aux_shuffle, configuration as the auxiliary model selected on each
#       split: λ=1, class weighting, 5 epochs; seeds 0-2). About 5.3 hours.
#   C.  The earliest 5% of the v4 labels (--frac_mode earliest, seeds 0-2): auxiliary 5 epochs; baseline 50 epochs (as for a random 5%).
#       About 1.3 hours.
#   D1. (after D0, if needed) seeds 0-4 for the configuration selected on each split; new training happens only where a D0
#       configuration is selected (4 runs per split, about 2.4 hours).
# Times estimated for an RTX 4090. Resumable after an interruption (--skip_existing).
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
