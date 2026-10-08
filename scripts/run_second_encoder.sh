#!/usr/bin/env bash
# 第二个编码器（10-07 用户同意）：在时间划分上换一个编码器，重复"有 / 无 v3.1 辅助任务"的比较，
# 回答"增益是不是 DeBERTa 特有的"。用法：bash scripts/run_second_encoder.sh [阶段…]（不带参数 = TUNE SEEDS）
#   TUNE   种子 0 的候选配置，与 DeBERTa 的做法相同（论文 6.2 节、表 S25）：
#          无辅助：类别加权 {无, inv_sqrt} × 轮数上限 {5, 10}，再加步数相当的 25 轮（类别加权）  → 5 次，约 1.1 小时
#          有辅助：λ {0.5, 1} × 类别加权 {无, inv_sqrt}，5 轮                                    → 4 次，约 2 小时
#          跑完后按验证集各选一个（src/second_encoder.py select）。
#   SEEDS  选中的两个配置各补种子 1–4（8 次，约 4 小时；无辅助若选中 5 轮则更短）。
# 默认模型 ehsanaghaei/SecureBERT（RoBERTa-base 结构，网络安全语料上预训练）。权重文件 pytorch_model.bin 约 500 MB，
# 首次运行时由 transformers 从 Hugging Face 镜像下载到服务器。时间按 DeBERTa-v3-base 在 RTX 4090 上的实测估计，合计约 7 小时。
# 支持中断后续跑（--skip_existing）。跑完把 results/encoder/T2_temporal_SecureBERT_* 取回本机，再运行 python src/second_encoder.py summary。
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
