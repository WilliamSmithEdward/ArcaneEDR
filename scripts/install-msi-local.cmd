@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-msi-local.ps1" %*
