@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0test-gui-scroll.ps1" %*
exit /b %ERRORLEVEL%
