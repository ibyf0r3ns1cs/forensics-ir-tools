@echo off
echo [*] Stopping Velociraptor service...
net stop velociraptor

echo [*] Starting Velociraptor manually for 20 seconds...
start "" "C:\Program Files\Velociraptor\Velociraptor.exe" ^
  --config "C:\Program Files\Velociraptor\client.config.yaml" ^
  service run

timeout /t 20 /nobreak >nul

echo [*] Stopping manual Velociraptor run...
taskkill /f /im Velociraptor.exe >nul 2>&1

echo [*] Starting Velociraptor service again...
net start velociraptor

echo [✓] Done.
