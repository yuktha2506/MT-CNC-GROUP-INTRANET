@echo off
title Server-Plant - create the Circulars folder
rem Creates the folder on this IIS server where circular attachments are kept:
rem   C:\server-plant\Circulars\General, IT, Quality, Marketing, HR, Safety, Production, Maintenance
rem Only SYSTEM (the intranet service) and Administrators can open it. IIS never
rem serves it directly (web.config hides it); employees open files through the intranet.
net session >nul 2>&1
if %errorlevel% neq 0 ( powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" & exit /b )
cd /d "%~dp0"
set "CDIR=%CD%\Circulars"
echo.
echo Creating %CDIR%
for %%D in (General IT Quality Marketing HR Safety Production Maintenance) do (
  if not exist "%CDIR%\%%D" mkdir "%CDIR%\%%D"
  if exist "%CDIR%\%%D" ( echo    OK  Circulars\%%D ) else ( echo    FAILED  Circulars\%%D )
)
echo.
echo Setting permissions (SYSTEM and Administrators only)
icacls "%CDIR%" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /T /C /Q
if errorlevel 1 ( echo    Permissions could not be set. ) else ( echo    OK )
echo.
findstr /C:"segment=\"Circulars\"" web.config >nul 2>&1
if errorlevel 1 (
  echo WARNING: web.config does not hide the Circulars folder yet.
  echo          Copy the new web.config from MTCNC-Intranet-Final.zip into %CD%.
) else (
  echo OK  web.config hides the Circulars folder from direct web access.
)
findstr /C:"CIRCULAR_ATTACH_ROOT" api.js >nul 2>&1
if errorlevel 1 (
  echo WARNING: api.js here is an older version. Copy the new api.js from the zip,
  echo          then run RESTART-SERVER-PLANT.bat.
)
echo.
echo Done. Attachments added to circulars will be saved in:
echo    %CDIR%\^<Department^>\
echo.
pause
