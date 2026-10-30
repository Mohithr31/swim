# JOCKY Windows Agent Launcher
Param(
    [string]$Server = "http://127.0.0.1:5000",
    [string]$AgentId = "",
    [string]$ApiKey = $env:JOCKY_API_KEY,
    [string]$Passphrase = ""
)

$ErrorActionPreference = "Stop"
$AgentDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent $AgentDir
Set-Location $Root

$PythonBin = "python"
if (Test-Path "$Root\venv\Scripts\python.exe") {
    $PythonBin = "$Root\venv\Scripts\python.exe"
} elseif (Test-Path "$Root\.venv\Scripts\python.exe") {
    $PythonBin = "$Root\.venv\Scripts\python.exe"
} elseif (Test-Path "$Root\.venv-windows\Scripts\python.exe") {
    $PythonBin = "$Root\.venv-windows\Scripts\python.exe"
}

if (-not $ApiKey -and $env:JOCKY_API_KEY) {
    $ApiKey = $env:JOCKY_API_KEY
}
if (-not $ApiKey) {
    $ApiKey = "JOCKY-DFIR-2026"
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "JOCKY Windows Agent - Windows Endpoint Launcher" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ("Connecting to Central Server: " + $Server) -ForegroundColor Yellow

$Arguments = @("-m", "agent.jocky_agent", "--server", $Server, "--api-key", $ApiKey)
if ($AgentId -ne "") { $Arguments += @("--id", $AgentId) }
if ($Passphrase -ne "") { $Arguments += @("--passphrase", $Passphrase) }

& $PythonBin @Arguments
exit $LASTEXITCODE

