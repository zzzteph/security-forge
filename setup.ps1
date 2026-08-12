# security-forge — first-time setup for a fresh copy (Windows / PowerShell).
# Installs the one Python dep, seeds .env, and creates the state dirs.

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

Write-Host "== security-forge setup ==" -ForegroundColor Cyan

# 1) Python dep (PyYAML). Everything else is stdlib.
Write-Host "-> installing Python deps (PyYAML)"
python -m pip install --quiet --upgrade -r requirements.txt

# 2) Seed .env from the template if missing (only needed for private-repo auth).
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "-> created .env  (optional: set GITHUB_TOKEN only for private targets)" -ForegroundColor Yellow
} else {
    Write-Host "-> .env already exists"
}

# 3) Remind about config.
$cfg = Get-Content "config.yaml" -Raw
if ($cfg -match 'repo:\s*""') {
    Write-Host "-> config.yaml: target.repo is still empty — set it before running." -ForegroundColor Yellow
}

# 4) Create the state dirs.
Write-Host "-> creating state dirs"
python scripts\pipeline.py setup

Write-Host ""
Write-Host "Setup done. Next:" -ForegroundColor Green
Write-Host "  1. Edit config.yaml  (target.repo = the GitHub URL to analyze)"
Write-Host "  2. Run a cycle:      claude   then type  /security-forge"
Write-Host "     or headless:      .\run_cycle.ps1"
Write-Host "  Findings are reported locally (stdout + knowledge/<target>/notifications.log)."
