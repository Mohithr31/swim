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
        & $cand -c "import flask" 2>$null
        if ($LASTEXITCODE -eq 0) {
            $PythonBin = $cand
            break
        }
    }
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " TINY MONITOR / JOCKY DFIR — Starting Canonical Server" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

& $PythonBin run.py @args
exit $LASTEXITCODE

