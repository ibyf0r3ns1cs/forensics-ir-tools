@echo off
setlocal EnableDelayedExpansion

REM Build timestamp YYYYMMDD_HHMMSS
set YYYY=%DATE:~10,4%
set MM=%DATE:~4,2%
set DD=%DATE:~7,2%
set HH=%TIME:~0,2%
set MI=%TIME:~3,2%
set SS=%TIME:~6,2%

REM Remove leading space from hour if exists
if "%HH:~0,1%"==" " set HH=0%HH:~1,1%

set LOGFILE=C:\ProgramData\velociraptor_fix_%YYYY%%MM%%DD%_%HH%%MI%%SS%.log
set VELO=C:\Program Files\Velociraptor\Velociraptor.exe
set CONF=C:\Program Files\Velociraptor\client.config.yaml

echo ======================================= >> "%LOGFILE%"
echo [%DATE% %TIME%] Velociraptor fix started >> "%LOGFILE%"
echo ======================================= >> "%LOGFILE%"

echo Stopping Velociraptor service...
sc stop velociraptor >> "%LOGFILE%" 2>&1

REM Wait until service is reported as STOPPED
:WAIT_STOP
sc query velociraptor | find "STOPPED" >nul
if errorlevel 1 (
    timeout /t 2 >nul
    goto WAIT_STOP
)

echo Service reported STOPPED. Waiting extra 30 seconds for cleanup...
timeout /t 30 /nobreak >nul

echo Starting Velociraptor manually with debug...
start "" /b "%VELO%" --config "%CONF%" service run -v --debug >> "%LOGFILE%" 2>&1

REM Give process time to initialize
timeout /t 5 >nul

REM Capture PID of the debug instance (best effort)
for /f "tokens=2 delims== " %%P in (
  'wmic process where "name='Velociraptor.exe'" get ProcessId /value ^| find "="'
) do set PID=%%P

echo Velociraptor debug PID=!PID! >> "%LOGFILE%"

timeout /t 120 /nobreak >nul

echo Stopping manual Velociraptor process PID !PID! ...
taskkill /f /pid !PID! >> "%LOGFILE%" 2>&1

echo Waiting 5 seconds before restarting service...
timeout /t 5 >nul

echo Starting Velociraptor service again...
sc start velociraptor >> "%LOGFILE%" 2>&1

echo [%DATE% %TIME%] Velociraptor fix completed >> "%LOGFILE%"
echo. >> "%LOGFILE%"

echo Done. Log written to %LOGFILE%

endlocal
