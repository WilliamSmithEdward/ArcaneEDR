@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0test-gui-payload.ps1" %*
