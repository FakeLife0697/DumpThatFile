@echo off
setlocal enabledelayedexpansion

:: Main script
if "%1"=="" (
    goto usage
)

echo Processing command: %1

if "%1"=="start" (
    echo Starting application...
    goto start_app
)
if "%1"=="stop" (
    echo Stopping application...
    goto stop
)

echo Error: Invalid command
goto usage

:start_app
echo Building and starting the application...
docker stop dumpthatfile 2>&1
docker rm dumpthatfile 2>&1
docker build -t dumpthatfile .
if %errorlevel% neq 0 (
    echo Error: Docker build failed
    exit /b 1
)

:: Run the container with proper port mapping
docker run -d -p 5000:5000 --name dumpthatfile dumpthatfile
:: docker run -d -p 3000:3000 --name dumpthatfile dumpthatfile

if %errorlevel% neq 0 (
    echo Error: Docker run failed
    exit /b 1
)

:: Wait a few seconds for the application to start
timeout /t 5 /nobreak > nul

:: Check if container is running
docker ps | findstr "dumpthatfile" > nul
if %errorlevel% neq 0 (
    echo Error: Container failed to start
    docker logs dumpthatfile
    exit /b 1
)
echo Checking container logs...
docker logs dumpthatfile
goto :eof

:stop
docker stop dumpthatfile 2>&1
docker rm dumpthatfile 2>&1
echo Application stopped successfully
goto :eof

:usage
echo Usage: %0 {start^|stop^}
echo.
echo Commands:
echo   start   - Start the application
echo   stop    - Stop the application
exit /b 1
