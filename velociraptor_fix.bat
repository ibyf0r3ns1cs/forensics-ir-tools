@echo off
set LOGFILE=C:\ProgramData\velociraptor_fix_log.txt

echo ======================================= >> "%LOGFILE%"
echo [%DATE% %TIME%] Velociraptor fix started >> "%LOGFILE%"
echo ======================================= >> "%LOGFILE%"

echo Stopping Velociraptor service...
net stop velociraptor >> "%LOGFILE%" 2>&1

echo Running Velociraptor manually with debug for 2 minutes...
start "" cmd /c ^
""C:\Program Files\Velociraptor\Velociraptor.exe" ^
 --config "C:\Program Files\Velociraptor\client.config.yaml" ^
 service run -v --debug >> "%LOGFILE%" 2>&1"

timeout /t 120 /nobreak >nul

echo Stopping manual Velociraptor process...
taskkill /f /im Velociraptor.exe >> "%LOGFILE%" 2>&1

echo Starting Velociraptor service again...
net start velociraptor >> "%LOGFILE%" 2>&1

echo [%DATE% %TIME%] Velociraptor fix completed >> "%LOGFILE%"
echo. >> "%LOGFILE%"

echo Done. Log written to %LOGFILE%
