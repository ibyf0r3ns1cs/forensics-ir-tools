@echo off
set LOGFILE=C:\ProgramData\velociraptor_fix_log.txt
set VELO="C:\Program Files\Velociraptor\Velociraptor.exe"
set CONF="C:\Program Files\Velociraptor\client.config.yaml"

echo ======================================= >> "%LOGFILE%"
echo [%DATE% %TIME%] Velociraptor fix started >> "%LOGFILE%"
echo ======================================= >> "%LOGFILE%"

echo Stopping Velociraptor service...
sc stop velociraptor >> "%LOGFILE%" 2>&1

REM Wait until service is fully stopped
:WAIT_STOP
sc query velociraptor | find "STOPPED" >nul
if errorlevel 1 (
    timeout /t 2 >nul
    goto WAIT_STOP
)

echo Starting Velociraptor manually with debug...
start "" /b "%VELO%" --config "%CONF%" service run -v --debug >> "%LOGFILE%" 2>&1

REM Capture PID of the started Velociraptor process
for /f "tokens=2 delims== " %%P in ('wmic process where "name='Velociraptor.exe'" get ProcessId /value ^| find "="') do set PID=%%P

echo Velociraptor PID=%PID% >> "%LOGFILE%"

timeout /t 120 /nobreak >nul

echo Stopping manual Velociraptor process PID %PID% ...
taskkill /f /pid %PID% >> "%LOGFILE%" 2>&1

echo Starting Velociraptor service again...
sc start velociraptor >> "%LOGFILE%" 2>&1

echo [%DATE% %TIME%] Velociraptor fix completed >> "%LOGFILE%"
echo. >> "%LOGFILE%"
