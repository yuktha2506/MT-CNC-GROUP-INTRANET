@echo off
setlocal
title Server-Plant - Setup
rem ======================================================================
rem  MT CNC-Group server-plant - one-click setup
rem  Right-click  ->  Run as administrator
rem  Users will open:  http://172.32.2.96:3001/
rem ======================================================================
set "APPPATH=C:\server-plant"
set "SITEIP=172.32.2.96"
set "PORT=3001"

net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Asking for administrator rights...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
cd /d "%~dp0"
if not exist "%~dp0backend.js" (
  echo  ERROR: backend.js not found. Keep this file in the server-plant folder.
  pause & exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup\server-plant-setup.ps1" -Source "%~dp0." -AppPath "%APPPATH%" -SiteIP "%SITEIP%" -Port %PORT%
echo.
echo  Full log: %~dp0setup\setup-log.txt
pause
