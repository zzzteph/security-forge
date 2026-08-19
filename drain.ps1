# security-forge — drain runner (Windows / PowerShell).
#
# orchestrate.py already drains the whole queue in one invocation (one isolated
# Claude session per repo, resumable from db\security-forge.db). This wrapper just
# relaunches it if the ORCHESTRATOR process itself dies, until the queue is empty.
#
#   .\drain.ps1 --org my-org           # sync the org, then drain every repo
#   .\drain.ps1 --user my-handle
#   .\drain.ps1                         # drain whatever is already queued
#   $env:MAX_CYCLES=5; .\drain.ps1 --org x
#   any extra flags pass straight through to orchestrate.py (--timeout, --model, …)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot
$maxCycles = if ($env:MAX_CYCLES) { [int]$env:MAX_CYCLES } else { 20 }
New-Item -ItemType Directory -Force -Path "logs" | Out-Null
$lock = "logs\.drain.lock"

if (Test-Path $lock) {
    $opid = Get-Content $lock -ErrorAction SilentlyContinue
    if ($opid -and (Get-Process -Id $opid -ErrorAction SilentlyContinue)) {
        Write-Host "[drain] another drain (pid $opid) is running; exiting."; exit 0
    }
}
$PID | Out-File -FilePath $lock -Encoding ascii
# mirror --rescan into the pending pre-check so a rescan-only queue isn't seen as empty
$rescan = if ($args -contains "--rescan") { @("--rescan") } else { @() }
function Get-Pending {
    try {
        $j = python scripts\orgdb.py pending @rescan 2>$null | ConvertFrom-Json
        return [int]$j.pending
    } catch { return 0 }
}

try {
    $i = 0
    $args = $args
    while ($true) {
        $p = Get-Pending
        Write-Host "[drain] pending=$p (cycle $i/$maxCycles)"
        if ($p -le 0) { Write-Host "[drain] queue empty — org fully analyzed. Done."; break }
        if ($i -ge $maxCycles) { Write-Host "[drain] hit MAX_CYCLES=$maxCycles; re-run .\drain.ps1 to continue."; break }
        $i++
        Write-Host "[drain] orchestrator cycle $i start"
        python orchestrate.py @args
        # after the first cycle the org is already synced; don't re-sync every relaunch
        $args = @("--no-sync") + $rescan
    }
}
finally {
    Remove-Item $lock -Force -ErrorAction SilentlyContinue
}
