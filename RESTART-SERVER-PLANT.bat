@echo off
title Server-Plant - Restart
net session >nul 2>&1
if %errorlevel% neq 0 ( powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" & exit /b )
echo Restarting the Node backend...
schtasks /End /TN "Server-Plant" >nul 2>&1
powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='node.exe'\" | Where-Object { $_.CommandLine -match 'backend\.js' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"
timeout /t 2 /nobreak >nul
schtasks /Run /TN "Server-Plant"
timeout /t 5 /nobreak >nul
powershell -NoProfile -Command "try { (Invoke-WebRequest http://127.0.0.1:3000/api/health -UseBasicParsing).Content } catch { 'Node is NOT answering - see C:\server-plant\logs\server.log' }"
pause
