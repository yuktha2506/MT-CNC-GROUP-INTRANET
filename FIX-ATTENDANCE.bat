@echo off
title Server-Plant - check eTimeTrack attendance
rem Checks that the new api.js is in place, that the eTimeTrack sign-in is in .env,
rem restarts the Node backend and confirms the attendance address answers.
net session >nul 2>&1
if %errorlevel% neq 0 ( powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" & exit /b )
cd /d "%~dp0"
echo.
echo 1/4  Checking api.js in %CD%
findstr /C:"attendanceRouter" api.js >nul 2>&1
if errorlevel 1 (
  echo      api.js here is the OLD version. Copy api.js from MTCNC-Intranet-Final.zip into %CD%
  echo      and run this file again.
  pause & exit /b 1
)
echo      OK - api.js has the eTimeTrack reader.
echo.
echo 2/4  Checking .env for the eTimeTrack sign-in
findstr /B /C:"ETIME_USER=" .env >nul 2>&1 && findstr /B /C:"ETIME_PASSWORD=" .env >nul 2>&1
if errorlevel 1 (
  echo      Not set yet - starting SET-ETIME-LOGIN.bat ...
  if not exist "SET-ETIME-LOGIN.bat" ( echo      SET-ETIME-LOGIN.bat is missing - copy it from the zip. & pause & exit /b 1 )
  call "SET-ETIME-LOGIN.bat"
) else (
  echo      OK - ETIME_USER and ETIME_PASSWORD are in .env.
)
echo.
echo 3/4  Restarting the Node backend (task Server-Plant)
schtasks /End /TN "Server-Plant" >nul 2>&1
powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='node.exe'\" | Where-Object { $_.CommandLine -match 'backend\.js' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"
timeout /t 2 /nobreak >nul
schtasks /Run /TN "Server-Plant" >nul
timeout /t 6 /nobreak >nul
echo.
echo 4/4  Asking the backend for /api/attendance/summary
powershell -NoProfile -Command ^
  "try { $r = Invoke-WebRequest http://127.0.0.1:3000/api/attendance/summary -UseBasicParsing; '      OK - answered ' + $r.StatusCode } catch { $c = 0; if ($_.Exception.Response) { $c = [int]$_.Exception.Response.StatusCode }; if ($c -eq 401) { '      OK - the attendance address exists (401 = sign-in needed, as expected). Refresh the Today page.' } elseif ($c -eq 404) { '      STILL OLD - the running server has no attendance address. Check that the Server-Plant task runs from ' + (Get-Location) + '.' } elseif ($c -eq 0) { '      Node is NOT answering - see logs\server.log' } else { '      Answered HTTP ' + $c } }"
echo.
echo After about 30 seconds the server saves what it read from eTimeTrack to:
echo      %CD%\logs\etime-last-page.html
echo If the Today page tiles stay empty, send that file to Claude (it holds no password).
echo.
pause
