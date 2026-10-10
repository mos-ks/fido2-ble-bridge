@echo off
rem One-command setup of fingerprint sign-in with a Bluetooth FIDO2 security key (asks for administrator rights).
"%WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\setup.ps1"
