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
if "%1"=="restart" (
    echo Restarting application...
    goto restart
)

echo Error: Invalid command
goto usage

:start_app
echo In start_app section

echo Building and starting the application...
docker build -t dumpthatfile .
if %errorlevel% neq 0 (
    echo Error: Docker build failed
    exit /b 1
)

:: Stop and remove existing container if it exists
docker stop dumpthatfile 2>nul
docker rm dumpthatfile 2>nul

:: Run the container with proper port mapping
docker run -d -p 5000:5000 --name dumpthatfile dumpthatfile
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
echo Stopping and removing container...
docker stop dumpthatfile 2>nul
docker rm dumpthatfile 2>nul
echo Application stopped successfully
goto :eof

:restart
echo In restart section
call :stop
call :start_app
goto :eof

:usage
echo Usage: %0 {start^|stop^|restart^}
echo.
echo Commands:
echo   start   - Start the application
echo   stop    - Stop the application
echo   restart - Restart the application
exit /b 1
