#!/usr/bin/env bash
# Watchdog on the server: guards scripts/run_review_gpu4.sh when unattended.
#   1. If the batch process disappears without writing its completion line -> restart (--skip_existing skips finished runs), at most 5 restarts;
#   2. if the log does not change for 60 minutes (training stuck) -> end the current training process; the batch script records it as
#      failed and continues with the next run;
#   3. after the batch has written its completion line, if any run failed -> run the batch again to redo the failed runs (at most twice);
#   4. with SHUTDOWN_WHEN_DONE=1, shut down after everything has finished successfully (default: no shutdown).
# Log: watchdog_gpu4.log. Start: setsid nohup bash scripts/watchdog_gpu4.sh > /dev/null 2>&1 < /dev/null &
cd "$(dirname "$0")/.." || exit 1
LOG=watchdog_gpu4.log
OUT=review_gpu4.out
say () { echo "$(date '+%F %T') $*" >> "$LOG"; }
running () { ps -eo args | grep -qE '^bash scripts/run_review_gpu4[.]sh'; }
start_batch () { (setsid nohup bash scripts/run_review_gpu4.sh >> "$OUT" 2>&1 < /dev/null &); }

restarts=0; repasses=0
pass_start=$(wc -l < "$OUT")          # 本轮批次在日志中的起始行（用来只看本轮的失败）
done_seen=$(grep -c '全部完成' "$OUT")
say "看门狗启动；已完成训练 $(grep -c '^TEST' "$OUT") 个；批次在运行：$(running && echo 是 || echo 否)"

while true; do
  sleep 300
  done_now=$(grep -c '全部完成' "$OUT")
  if [ "$done_now" -gt "$done_seen" ]; then         # 本轮批次跑完了
    done_seen=$done_now
    fails=$(tail -n +"$pass_start" "$OUT" | grep -c '^!!!!!')
    if [ "$fails" -gt 0 ] && [ "$repasses" -lt 2 ]; then
      repasses=$((repasses + 1)); pass_start=$(wc -l < "$OUT")
      say "批次完成，但本轮有 $fails 个失败；第 $repasses 遍补跑"
      start_batch; continue
    fi
    say "全部完成：训练 $(grep -c '^TEST' "$OUT") 个；最后一轮失败 $fails 个"
    if [ "${SHUTDOWN_WHEN_DONE:-0}" = 1 ] && [ "$fails" -eq 0 ]; then
      say "按设置关机"; sync; sleep 5; shutdown -h now 2>>"$LOG" || poweroff 2>>"$LOG"
    fi
    exit 0
  fi
  if ! running; then                                # 没完成就消失了
    if [ "$restarts" -ge 5 ]; then say "已重启 5 次仍停止，放弃"; exit 1; fi
    restarts=$((restarts + 1)); pass_start=$(wc -l < "$OUT")
    say "批次进程消失（未完成）；第 $restarts 次重启"
    start_batch; continue
  fi
  age=$(( $(date +%s) - $(stat -c %Y "$OUT") ))
  if [ "$age" -gt 3600 ]; then                      # 日志 60 分钟没动：训练卡死
    pid=$(pgrep -f 'python src/train_encoder[.]py' | head -1)
    say "日志 ${age} 秒没有变化，结束卡住的训练进程 ${pid:-（没找到）}"
    [ -n "$pid" ] && kill "$pid"
  fi
done
