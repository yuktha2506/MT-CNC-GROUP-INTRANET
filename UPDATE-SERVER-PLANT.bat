@echo off
setlocal
title Server-Plant - Update to Plant Hub
rem ======================================================================
rem  Applies the new Plant Hub design to C:\server-plant
rem  Right-click  ->  Run as administrator
rem  Keeps your data settings, backs up the old files, sets the Admin
rem  password, restarts Node and checks http://172.32.2.96:3001/
rem ======================================================================
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Asking for administrator rights...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup\update.ps1" -Source "%~dp0." -AppPath "C:\server-plant" -SiteIP "172.32.2.96" -Port 3001
echo.
echo  Log: %~dp0setup\update-log.txt
pause
