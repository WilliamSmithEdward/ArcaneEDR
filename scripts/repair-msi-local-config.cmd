@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0repair-msi-local-config.ps1" %*
