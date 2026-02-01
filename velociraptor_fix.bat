@echo off
setlocal EnableDelayedExpansion

REM Build timestamp YYYYMMDD_HHMMSS (depends on locale date format)
set YYYY=%DATE:~10,4%
set MM=%DATE:~4,2%
set DD=%DATE:~7,2%
set HH=%TIME:~0,2%
set MI=%TIME:~3,2%
set SS=%TIME:~6,2%
if "%HH:~0,1%"==" " set HH=0%HH:~1,1%

set LOGMAIN=C:\ProgramData\velociraptor_fix_%YYYY%%MM%%DD%_%HH%%MI%%SS%.log
set LOGVELO=C:\ProgramData\velociraptor_debug_%YYYY%%MM%%DD%_%HH%%MI%%SS%.log

set VELO=C:\Program Files\Velociraptor\Velociraptor.exe
set CONF=C:\Program Files\Velociraptor\client.config.yaml

echo ======================================= >> "%LOGMAIN%"
echo [%DATE% %TIME%] Velociraptor fix started >> "%LOGMAIN%"
echo Script log: %LOGMAIN% >> "%LOGMAIN%"
echo Velociraptor debug log: %LOGVELO% >> "%LOGMAIN%"
echo ======================================= >> "%LOGMAIN%"

echo Stopping Velociraptor service...
sc stop velociraptor >> "%LOGMAIN%" 2>&1

REM Wait until service is reported as STOPPED
:WAIT_STOP
sc query velociraptor | find "STOPPED" >nul
if errorlevel 1 (
    timeout /t 2 >nul
    goto WAIT_STOP
)

echo Service reported STOPPED. Waiting extra 30 seconds for cleanup...
timeout /t 30 /nobreak >nul

echo Starting Velociraptor manually with debug (120 seconds)...
echo [%DATE% %TIME%] Starting manual run >> "%LOGMAIN%"

REM Start Velociraptor and redirect ONLY its output to LOGVELO (separate file)
start "" /b "%VELO%" --config "%CONF%" service run -v --debug >> "%LOGVELO%" 2>&1

REM Give process time to initialize
timeout /t 5 >nul

REM Capture PID for the most recent Velociraptor.exe (best-effort)
set PID=
for /f "skip=1 tokens=2 delims=," %%P in ('wmic process where "name='Velociraptor.exe'" get ProcessId /format:csv') do (
  if not "%%P"=="" set PID=%%P
)

echo Velociraptor manual PID=!PID! >> "%LOGMAIN%"

timeout /t 120 /nobreak >nul

echo Stopping manual Velociraptor process PID !PID! ...
taskkill /f /pid !PID! >> "%LOGMAIN%" 2>&1

echo Waiting 5 seconds before restarting service...
timeout /t 5 >nul

echo Starting Velociraptor service again...
sc start velociraptor >> "%LOGMAIN%" 2>&1

echo [%DATE% %TIME%] Velociraptor fix completed >> "%LOGMAIN%"
echo. >> "%LOGMAIN%"

echo Done.
echo Script log: %LOGMAIN%
echo Velociraptor debug log: %LOGVELO%

endlocal
