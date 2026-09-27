# JOCKY Windows Agent Launcher
Param(
    [string]$Server = "http://127.0.0.1:5000",
    [string]$AgentId = "",
    [string]$Passphrase = ""
)

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "JOCKY Windows Agent - Windows Endpoint Launcher" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ("Connecting to Central Server: " + $Server) -ForegroundColor Yellow

$Arguments = @("-m", "agent.jocky_agent", "--server", $Server)
if ($AgentId -ne "") { $Arguments += @("--id", $AgentId) }
if ($Passphrase -ne "") { $Arguments += @("--passphrase", $Passphrase) }

& python @Arguments
exit $LASTEXITCODE
