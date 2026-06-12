@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0test-msi-validation.ps1" %*
