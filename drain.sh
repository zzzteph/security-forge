#!/usr/bin/env bash
# security-forge — drain runner (Linux / macOS / WSL / git-bash).
#
# orchestrate.py already drains the whole queue in one invocation (one isolated
# Claude session per repo, resumable from db/security-forge.db). This wrapper just
# relaunches it if the ORCHESTRATOR process itself dies, until the queue is empty.
#
#   ./drain.sh --org my-org            # sync the org, then drain every repo
#   ./drain.sh --user my-handle
#   ./drain.sh                          # drain whatever is already queued
#   MAX_CYCLES=5 ./drain.sh --org x     # cap orchestrator relaunches this run
#   any extra flags pass straight through to orchestrate.py (--timeout, --model, …)
set -euo pipefail
cd "$(dirname "$0")"
MAX_CYCLES="${MAX_CYCLES:-20}"
mkdir -p logs
lock="logs/.drain.lock"

if [ -f "$lock" ] && kill -0 "$(cat "$lock" 2>/dev/null)" 2>/dev/null; then
  echo "[drain] another drain (pid $(cat "$lock")) is running; exiting."; exit 0
fi
echo $$ > "$lock"; trap 'rm -f "$lock"' EXIT

# mirror --rescan into the pending pre-check so a rescan-only queue isn't seen as empty
rescan=""; for a in "$@"; do [ "$a" = "--rescan" ] && rescan="--rescan"; done
pending() {
  python scripts/orgdb.py pending $rescan 2>/dev/null \
    | python -c 'import sys,json; print(json.load(sys.stdin).get("pending",0))' 2>/dev/null \
    || echo 0
}

i=0
args=("$@")
while :; do
  p="$(pending)"
  echo "[drain] pending=$p (cycle $i/$MAX_CYCLES)"
  [ "${p:-0}" -le 0 ] && { echo "[drain] queue empty — org fully analyzed. Done."; break; }
  [ "$i" -ge "$MAX_CYCLES" ] && { echo "[drain] hit MAX_CYCLES=$MAX_CYCLES; re-run ./drain.sh to continue."; break; }
  i=$((i + 1))
  echo "[drain] orchestrator cycle $i start"
  python orchestrate.py "${args[@]}" || echo "[drain] orchestrator exited non-zero — relaunching"
  # after the first cycle the org is already synced; don't re-sync every relaunch
  args=(--no-sync $rescan)
done
