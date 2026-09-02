@echo off
title Push Cyber Sentinel to GitHub
color 0A
cd /d "%~dp0"
echo =====================================================
echo   CYBER SENTINEL - 1-CLICK GITHUB SYNC
echo =====================================================
echo.
echo [1/3] Adding all files to Git...
git add .
echo [2/3] Committing changes...
git commit -m "Update Cyber Sentinel"
echo [3/3] Pushing to GitHub...
git branch -M main
git push -u origin main --force
echo.
echo ====================================================
echo   SUCCESS! Repository successfully pushed to GitHub!
esho ====================================================
pause