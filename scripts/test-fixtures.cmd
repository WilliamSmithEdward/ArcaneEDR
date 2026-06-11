@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0test-fixtures.ps1" %*
exit /b %ERRORLEVEL%
