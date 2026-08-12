# security-forge — headless cycle runner (Windows / PowerShell).
#
# Runs ONE pipeline cycle unattended via Claude Code, then exits. Point Windows
# Task Scheduler at this file to run "from time to time".
#
# Register a scheduled task (every 6 hours, example):
#   $action  = New-ScheduledTaskAction -Execute "powershell.exe" `
#                -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PWD\run_cycle.ps1`""
#   $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) `
#                -RepetitionInterval (New-TimeSpan -Hours 6)
#   Register-ScheduledTask -TaskName "security-forge-<target>" -Action $action -Trigger $trigger
#
# Unregister:  Unregister-ScheduledTask -TaskName "security-forge-<target>" -Confirm:$false

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

New-Item -ItemType Directory -Force -Path "$PSScriptRoot\logs" | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$log   = "$PSScriptRoot\logs\cycle-$stamp.log"
$lock  = "$PSScriptRoot\logs\.cycle.lock"

# Prevent overlapping cycles (a run can outlast the scheduler interval).
if (Test-Path $lock) {
    $age = (Get-Date) - (Get-Item $lock).LastWriteTime
    if ($age.TotalHours -lt 12) {
        "[security-forge] a cycle is already running (lock age $([int]$age.TotalMinutes)m); skipping." |
            Tee-Object -FilePath $log -Append
        exit 0
    }
    Remove-Item $lock -Force   # stale lock
}
New-Item -ItemType File -Path $lock -Force | Out-Null

# Target repo: SECFORGE_TARGET_REPO env (else config.yaml). Set it before running
# to point this cycle at a specific repo, e.g. $env:SECFORGE_TARGET_REPO = "https://github.com/owner/repo".
$repo = if ($env:SECFORGE_TARGET_REPO) { $env:SECFORGE_TARGET_REPO } else { "the configured target repo" }
$prompt = @"
Follow opt/workflow.md to run exactly one full security analysis cycle against $repo.
Work fully non-interactively: never ask questions, make reasonable choices, honour the
notify-only guardrail (never block or raise a PR — local report only), and
finish by tearing down the docker sandbox. This is an automated scheduled run.
"@

# Optional: pin a stronger model for analysis by adding e.g. --model opus below.
$claudeArgs = @("-p", $prompt, "--dangerously-skip-permissions")

try {
    "[security-forge] cycle start $stamp" | Tee-Object -FilePath $log -Append
    & claude @claudeArgs 2>&1 | Tee-Object -FilePath $log -Append
    "[security-forge] cycle end (exit $LASTEXITCODE)" | Tee-Object -FilePath $log -Append
}
catch {
    "[security-forge] ERROR: $_" | Tee-Object -FilePath $log -Append
}
finally {
    Remove-Item $lock -Force -ErrorAction SilentlyContinue
    # Keep the last 40 logs.
    Get-ChildItem "$PSScriptRoot\logs\cycle-*.log" | Sort-Object LastWriteTime -Descending |
        Select-Object -Skip 40 | Remove-Item -Force -ErrorAction SilentlyContinue
}
