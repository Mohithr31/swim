# Tiny Monitor / JOCKY DFIR — Windows Agent Launcher
Param(
    [string]$Server = "http://127.0.0.1:5000",
    [string]$AgentId = "",
    [string]$ApiKey = $env:JOCKY_API_KEY,
    [string]$Passphrase = "",
    [switch]$Once,
    [switch]$Snapshot,
    [switch]$Live,
    [string]$CaseId = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$PythonCandidates = @(
    "$Root\venv\Scripts\python.exe",
    "$Root\.venv\Scripts\python.exe",
    "$Root\.venv-windows\Scripts\python.exe",
    "python"
)
$PythonBin = "python"
foreach ($cand in $PythonCandidates) {
    if ($cand -eq "python" -or (Test-Path $cand -ErrorAction SilentlyContinue)) {
        & $cand -c "import requests" 2>$null
        if ($LASTEXITCODE -eq 0) {
            $PythonBin = $cand
            break
        }
    }
}

if (-not $ApiKey -and $env:JOCKY_API_KEY) {
    $ApiKey = $env:JOCKY_API_KEY
}
if (-not $ApiKey) {
    $ApiKey = "JOCKY-DFIR-2026"
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " TINY MONITOR / JOCKY DFIR — Starting Endpoint Agent" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host (" Target Server: " + $Server) -ForegroundColor Yellow

$Arguments = @("-m", "agent.jocky_agent", "--server", $Server, "--api-key", $ApiKey)
if ($AgentId) { $Arguments += @("--id", $AgentId) }
if ($Passphrase) { $Arguments += @("--passphrase", $Passphrase) }
if ($Once) { $Arguments += @("--once") }
if ($Snapshot) { $Arguments += @("--snapshot") }
if ($Live) { $Arguments += @("--live") }
if ($CaseId) { $Arguments += @("--case-id", $CaseId) }

& $PythonBin @Arguments
exit $LASTEXITCODE
