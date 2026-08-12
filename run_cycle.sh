#!/usr/bin/env bash
# security-forge — headless cycle runner (Linux / macOS / WSL / git-bash).
# Runs ONE pipeline cycle unattended via Claude Code, then exits.
#
# Cron example (every 6 hours):
#   0 */6 * * * /path/to/security-forge/run_cycle.sh >> /path/to/security-forge/logs/cron.log 2>&1
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p logs
stamp="$(date +%Y%m%d-%H%M%S)"
log="logs/cycle-${stamp}.log"
lock="logs/.cycle.lock"

# Prevent overlapping cycles.
if [ -f "$lock" ]; then
  if [ "$(( $(date +%s) - $(stat -c %Y "$lock" 2>/dev/null || stat -f %m "$lock") ))" -lt 43200 ]; then
    echo "[security-forge] a cycle is already running; skipping." | tee -a "$log"; exit 0
  fi
  rm -f "$lock"
fi
touch "$lock"
trap 'rm -f "$lock"' EXIT

# Target repo: first arg, else SECFORGE_TARGET_REPO env, else config.yaml.
REPO="${1:-${SECFORGE_TARGET_REPO:-}}"
export SECFORGE_TARGET_REPO="$REPO"

PROMPT="Follow opt/workflow.md to run exactly one full security analysis cycle against ${REPO:-the configured target repo}. Work fully non-interactively: never ask questions, make reasonable choices, honour the notify-only guardrail (never block or raise a PR — local report only), and finish by tearing down the docker sandbox. This is an automated scheduled run."

echo "[security-forge] cycle start $stamp" | tee -a "$log"
# Add e.g. --model opus for stronger analysis.
claude -p "$PROMPT" --dangerously-skip-permissions 2>&1 | tee -a "$log"
echo "[security-forge] cycle end" | tee -a "$log"

# Keep the last 40 logs.
ls -1t logs/cycle-*.log 2>/dev/null | tail -n +41 | xargs -r rm -f
