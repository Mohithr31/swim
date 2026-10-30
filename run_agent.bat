@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ======================================================================
echo    TINY MONITOR / JOCKY DFIR — Starting Endpoint Agent
echo ======================================================================

set PYTHON_BIN=python
if exist "%~dp0venv\Scripts\python.exe" (
    "%~dp0venv\Scripts\python.exe" -c "import requests" >nul 2>&1
    if not errorlevel 1 set "PYTHON_BIN=%~dp0venv\Scripts\python.exe"
) else if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" -c "import requests" >nul 2>&1
    if not errorlevel 1 set "PYTHON_BIN=%~dp0.venv\Scripts\python.exe"
) else if exist "%~dp0.venv-windows\Scripts\python.exe" (
    "%~dp0.venv-windows\Scripts\python.exe" -c "import requests" >nul 2>&1
    if not errorlevel 1 set "PYTHON_BIN=%~dp0.venv-windows\Scripts\python.exe"
)

if "%JOCKY_API_KEY%"=="" set JOCKY_API_KEY=JOCKY-DFIR-2026
if "%JOCKY_SERVER%"=="" set JOCKY_SERVER=http://127.0.0.1:5000

"%PYTHON_BIN%" -m agent.jocky_agent --server "%JOCKY_SERVER%" --api-key "%JOCKY_API_KEY%" %*
if errorlevel 1 (
    echo.
    echo [ERROR] Agent terminated with an error.
    pause
)

