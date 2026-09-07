@echo off
setlocal
cd /d "%~dp0"
title GraviTrack - Local Server
where node >nul 2>&1
if errorlevel 1 (
  echo.
  echo Node.js is not installed or is not on PATH.
  echo Install Node.js 18 or newer, then run this file again.
  echo.
  pause
  exit /b 1
)
if not exist data mkdir data
set OPEN_BROWSER=true
node server.js
pause
