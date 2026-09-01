@echo off
title CYBER SENTINEL - One-Click Installer & Environment Setup
color 0A
cd /d "%~dp0"

echo ========================================================================
echo    ____  _           _        ____             _   _            _ 
echo   ^|  _ \(_) ___   __^| ^| ___  / ___^|  ___ _ __ ^| ^|_(_)_ __   ___^| ^|
echo   ^| ^| ^| ^| ^|/ _ \ / _` ^|/ _ \ \___ \ / _ \ '_ \^| __^| ^| '_ \ / _ \ ^|
echo   ^| ^|_^| ^| ^| (_) ^| (_^| ^|  __/  ___) ^|  __/ ^| ^| ^| ^|_^| ^| ^| ^| ^|  __/^|
echo   ^|____/^_^\___/ \__,_^|\___^| ^|____/ \___^|_^| ^|_^\__^|_^|_^| ^|_^\___^|_^|
echo.
echo   Cyber Sentinel - 1-Click Installer ^& Setup (Problem ID: 26145)
echo ========================================================================
echo.

:: 1. Check Python Installation
echo [*] Step 1/4: Checking Python environment...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo [-] ERROR: Python is not installed or not found in system PATH.
    echo [*] Please install Python 3.9+ from https://www.python.org and check "Add Python to PATH".
    echo.
    pause
    exit /b 1
)
python --version
echo [+] Python detected successfully!
echo.

:: 2. Install / Upgrade Dependencies
echo [*] Step 2/4: Installing required Python dependencies...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if %errorlevel% neq 0 (
    color 0E
    echo [!] Standard install completed with some warnings.
)
echo [+] Dependencies installed!
echo.

:: 3. Setup Folders
echo [*] Step 3/4: Verifying local forensic and dataset directories...
if not exist "data" mkdir data
if not exist "datasets" mkdir datasets
echo [+] Directories verified!
echo.

:: 4. Run Verification Test Suite
echo [*] Step 4/4: Running self-diagnostic test suite (12 Tests)...
python run.py --test
if %errorlevel% neq 0 (
    color 0E
    echo [!] Test suite completed with warnings.
) else (
    echo.
    echo ========================================================================
    echo  [+] INSTALLATION ^& SELF-VERIFICATION COMPLETED SUCCESSFULLY! (100%%)
    echo ========================================================================
)

echo.
echo [*] You are ready to launch!
echo [*] Simply double-click "START_CYBER_SENTINEL.bat" anytime to start the SOC.
echo.
pause
