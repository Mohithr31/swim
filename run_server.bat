@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ======================================================================
echo    TINY MONITOR / JOCKY DFIR — Starting Canonical Server
echo ======================================================================

set PYTHON_BIN=python
if exist "%~dp0venv\Scripts\python.exe" (
    "%~dp0venv\Scripts\python.exe" -c "import flask" >nul 2>&1
    if not errorlevel 1 set "PYTHON_BIN=%~dp0venv\Scripts\python.exe"
) else if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" -c "import flask" >nul 2>&1
    if not errorlevel 1 set "PYTHON_BIN=%~dp0.venv\Scripts\python.exe"
) else if exist "%~dp0.venv-windows\Scripts\python.exe" (
    "%~dp0.venv-windows\Scripts\python.exe" -c "import flask" >nul 2>&1
    if not errorlevel 1 set "PYTHON_BIN=%~dp0.venv-windows\Scripts\python.exe"
)

"%PYTHON_BIN%" run.py %*
if errorlevel 1 (
    echo.
    echo [ERROR] Server terminated with an error.
    pause
)

