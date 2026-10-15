#!/usr/bin/env bash
# Second encoder: repeats the comparison with and without the v3.1 auxiliary task on the temporal split with another encoder,
# to check whether the gain is specific to DeBERTa. Usage: bash scripts/run_second_encoder.sh [stage...] (no argument = TUNE SEEDS)
#   TUNE   seed-0 candidate configurations, as for DeBERTa (Section 6.2, Table S25):
#          baseline: class weighting {none, inv_sqrt} × epoch cap {5, 10}, plus the step-matched 25 epochs (class-weighted)  -> 5 runs, about 1.1 hours
#          auxiliary: λ {0.5, 1} × class weighting {none, inv_sqrt}, 5 epochs                                              -> 4 runs, about 2 hours
#          afterwards one configuration each is selected on the validation set (src/second_encoder.py select).
#   SEEDS  seeds 1-4 for the two selected configurations (8 runs, about 4 hours; shorter if the baseline selects 5 epochs).
# Default model ehsanaghaei/SecureBERT (RoBERTa-base architecture, pre-trained on cybersecurity text). Its weights pytorch_model.bin
# (about 500 MB) are downloaded to the server by transformers from a Hugging Face mirror on the first run. Times estimated from
# DeBERTa-v3-base on an RTX 4090, about 7 hours in total.
# Resumable after an interruption (--skip_existing). Afterwards, copy results/encoder/T2_temporal_SecureBERT_* to the local machine and
# run python src/second_encoder.py summary.
set -o pipefail
cd "$(dirname "$0")/.."
source /usr/local/miniconda3/bin/activate py312 2>/dev/null || true
export HF_ENDPOINT=${HF_ENDPOINT:-https://hf-mirror.com}
command -v python > /dev/null || { echo "!!!!! 找不到 python（需要先激活 py312 环境）"; exit 1; }
MODEL=${MODEL:-ehsanaghaei/SecureBERT}
PHASES=${*:-TUNE SEEDS}
mkdir -p results/encoder
LOG=results/encoder/log_second_encoder_$(date +%Y%m%d_%H%M).txt
run () {
  echo "===== $(date '+%F %T') $* =====" | tee -a "$LOG"
  python src/train_encoder.py --model "$MODEL" --task T2 --split temporal --source_mode none --skip_existing "$@" 2>&1 | tee -a "$LOG" \
    || echo "!!!!! 失败（已跳过，继续下一个）：$*" | tee -a "$LOG"
}
echo "===== 模型：$MODEL；阶段：$PHASES =====" | tee -a "$LOG"

for PH in $PHASES; do
  echo "===== $(date '+%F %T') 阶段 $PH 开始 =====" | tee -a "$LOG"
  case "$PH" in
    TUNE)
      # 最短的一次（约 6.5 分钟）放在最前面：模型加载或分词有问题时能尽早发现
      for E in 5 10; do
        for CW in none inv_sqrt; do
          run --seed 0 --class_weight "$CW" --epochs "$E"
        done
      done
      run --seed 0 --class_weight inv_sqrt --epochs 25
      for LAM in 0.5 1.0; do
        for CW in none inv_sqrt; do
          run --seed 0 --aux_v31 --aux_lambda "$LAM" --class_weight "$CW" --epochs 5
        done
      done
      python src/second_encoder.py select --model "$MODEL" 2>&1 | tee -a "$LOG" ;;
    SEEDS)
      SEL=$(python src/second_encoder.py select --model "$MODEL" --shell) || { echo "!!!!! 候选配置没有跑全，无法选择；先跑 TUNE" | tee -a "$LOG"; exit 1; }
      eval "$SEL"
      echo "选中的配置：无辅助 $NONE_ARGS；有辅助 $AUX_ARGS" | tee -a "$LOG"
      for SEED in 1 2 3 4; do
        run --seed "$SEED" $AUX_ARGS
        run --seed "$SEED" $NONE_ARGS
      done ;;
    *) echo "未知阶段：$PH（可用：TUNE SEEDS）" | tee -a "$LOG" ;;
  esac
done
echo "===== $(date '+%F %T') 全部完成，日志：$LOG =====" | tee -a "$LOG"
