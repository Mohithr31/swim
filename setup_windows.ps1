$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root
py -3 -m venv .venv-windows
& .\.venv-windows\Scripts\python.exe -m pip install --upgrade pip
& .\.venv-windows\Scripts\python.exe -m pip install -r requirements.txt
& .\.venv-windows\Scripts\python.exe -m py_compile server/server.py agent/jocky_agent.py
Write-Host "[JOCKY] Windows environment ready. Run .\run_server.ps1 and .\agent\run_agent.ps1"
