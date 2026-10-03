#!/usr/bin/env bash
# 服务器端看门狗（10-02 用户本地要断电时写）：无人值守时守护 scripts/run_review_gpu4.sh。
#   1. 批次进程没写"全部完成"就消失 → 自动重启（--skip_existing 跳过已完成的训练），最多重启 5 次；
#   2. 日志 60 分钟没有任何变化（训练卡死）→ 结束当前训练进程，批次脚本会记为失败并继续下一个；
#   3. 批次写完"全部完成"后，若本轮有失败的训练 → 再跑一遍批次补跑失败的（最多补 2 遍）；
#   4. SHUTDOWN_WHEN_DONE=1 时，全部成功完成后关机（默认不关）。
# 记录：watchdog_gpu4.log。启动：setsid nohup bash scripts/watchdog_gpu4.sh > /dev/null 2>&1 < /dev/null &
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
