@echo off
title CYBER SENTINEL - Real-Time AI Threat Detection SOC (SIH 26145)
color 0B
cd /d "%~dp0"

echo ========================================================================
echo    ____  _           _        ____             _   _            _ 
echo   ^|  _ \(_) ___   __^| ^| ___  / ___^|  ___ _ __ ^| ^|_(_)_ __   ___^| ^|
echo   ^| ^| ^| ^| ^|/ _ \ / _` ^|/ _ \ \___ \ / _ \ '_ \^| __^| ^| '_ \ / _ \ ^|
echo   ^| ^|_^| ^| ^| (_) ^| (_^| ^|  __/  ___) ^|  __/ ^| ^| ^| ^|_^| ^| ^| ^| ^|  __/^|
echo   ^|____/^_^\___/ \__,_^|\___^| ^|____/ \___^|_^| ^|_^\__^|_^|_^| ^|_^\___^|_^|
echo.
echo   Passive Unidirectional Threat Detection Platform (Problem ID 26145)
echo ========================================================================
echo.

:: 1. Free Port 8000 from any previous instances
echo [*] Checking and freeing Port 8000...
powershell -Command "$conn = Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue; if ($conn) { $conn.OwningProcess | Select-Object -Unique | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue } }" >nul 2>&1
timeout /t 1 /nobreak >nul

:: 2. Launch Cyber Sentinel Master Runner
echo [*] Starting Cyber Sentinel AI Engine...
echo [*] SOC Dashboard will open at: http://localhost:8000
echo.

if exist "run.py" (
    python run.py --web
) else if exist "cyber_sentinel_all_in_one.py" (
    python cyber_sentinel_all_in_one.py --web
) else if exist "hackathon\run.py" (
    cd hackathon
    python run.py --web
)

pause
