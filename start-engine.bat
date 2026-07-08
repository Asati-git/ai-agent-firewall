@echo off
title Cerberus Engine
cd /d "%~dp0"
echo.
echo   Cerberus engine  -  http://127.0.0.1:9000/
echo   Close this window (or press Ctrl+C) to stop the engine.
echo.
node "%~dp0bin\cerberus.mjs" engine
echo.
echo Engine stopped. Press any key to close...
pause >nul
