@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title FileScope Builder

where powershell.exe >nul 2>&1
if errorlevel 1 (
    echo ERROR: Windows PowerShell was not found.
    pause
    exit /b 1
)

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1"
set "BUILD_RC=%ERRORLEVEL%"

if not "%BUILD_RC%"=="0" (
    echo.
    echo BUILD FAILED.
    if exist "%~dp0FileScope_build_error.txt" echo Review FileScope_build_error.txt for details.
    echo.
    pause
    exit /b %BUILD_RC%
)

echo.
echo BUILD COMPLETE
echo Output: "%~dp0dist\FileScope.exe"
echo.
pause
exit /b 0
