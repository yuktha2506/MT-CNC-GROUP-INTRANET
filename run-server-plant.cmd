@echo off
cd /d "C:\server-plant"
:loop
echo [%date% %time%] starting backend.js>> "C:\server-plant\logs\server.log"
"C:\server-plant\runtime\node.exe" backend.js >> "C:\server-plant\logs\server.log" 2>&1
echo [%date% %time%] backend.js stopped, restarting in 5 s>> "C:\server-plant\logs\server.log"
ping -n 6 127.0.0.1 >nul
goto loop