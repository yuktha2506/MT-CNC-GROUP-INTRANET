@echo off
title Server-Plant - Check
net session >nul 2>&1
if %errorlevel% neq 0 ( powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" & exit /b )
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup\server-plant-setup.ps1" -AppPath "C:\server-plant" -SiteIP "172.32.2.96" -Port 3001 -CheckOnly
echo.
echo  Last 20 lines of C:\server-plant\logs\server.log:
powershell -NoProfile -Command "Get-Content 'C:\server-plant\logs\server.log' -Tail 20"
pause
