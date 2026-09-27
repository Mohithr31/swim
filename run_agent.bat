@echo off
setlocal
cd /d "%~dp0"
if "%JOCKY_API_KEY%"=="" set JOCKY_API_KEY=JOCKY-DFIR-2026
if "%JOCKY_SERVER%"=="" set JOCKY_SERVER=http://127.0.0.1:5000
python -m agent.jocky_agent --server "%JOCKY_SERVER%" --api-key "%JOCKY_API_KEY%" %*
if errorlevel 1 pause
