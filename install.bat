@echo off
echo.
echo ========================================
echo    NPM Scanner - Windows Installation
echo ========================================
echo.

REM Check for Node.js
where node >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Node.js is not installed or not in PATH
    echo Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

REM Check for NPM
where npm >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: NPM is not installed or not in PATH
    pause
    exit /b 1
)

echo [1/4] Installing dependencies...
call npm install

if %errorlevel% neq 0 (
    echo.
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo [2/4] Creating global link...
call npm link

if %errorlevel% neq 0 (
    echo.
    echo ERROR: Failed to create global link
    echo Try running this script as Administrator
    pause
    exit /b 1
)

echo.
echo [3/4] Verifying installation...
call npm-scanner --version >nul 2>&1

if %errorlevel% equ 0 (
    echo.
    echo [4/4] Installation successful!
    echo.
    echo ========================================
    echo    Installation Complete!
    echo ========================================
    echo.
    echo You can now use these commands:
    echo   - npm-scanner     (full command)
    echo   - nscan           (short alias)
    echo   - npm-scanner -i  (interactive mode)
    echo.
    echo Try it now: nscan
    echo.
) else (
    echo.
    echo WARNING: Installation completed but verification failed
    echo Please open a new Command Prompt and try: npm-scanner --version
    echo.
)

pause