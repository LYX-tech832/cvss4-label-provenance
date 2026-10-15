#!/usr/bin/env bash
# W3, first batch of GPU runs: DeBERTa-v3-base, one random seed.
#   Main runs: T2 (description only) × {temporal, leave out VulnCheck, leave out GitHub_M, leave out VulDB} × {plain, + v3.1 auxiliary task} = 8 runs
#   Control:   T1 temporal × plain = 1 run
#   Analysis:  T2 temporal × {source features, source habit matrices} = 2 runs
# Usage (from the project root): bash scripts/run_w3.sh
# Other model: MODEL=answerdotai/ModernBERT-base bash scripts/run_w3.sh; other seed: SEED=1 bash scripts/run_w3.sh
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
