@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0test-gui-alerts.ps1"
exit /b %ERRORLEVEL%
