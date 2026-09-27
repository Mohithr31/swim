@echo off
setlocal
cd /d "%~dp0"
python -m server.server
if errorlevel 1 pause
