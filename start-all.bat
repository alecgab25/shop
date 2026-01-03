@echo off
setlocal
rem Launch backend (Express) and frontend (Vite) in separate windows.
cd /d "%~dp0"

start "GlowUp API" cmd /k "npm start"
start "GlowUp Frontend" cmd /k "cd /d \"%~dp0clerk-javascript\" && npm run dev"

echo Servers starting... Backend on http://localhost:3000 and frontend on http://localhost:5173/
echo You can close this window now; check the opened terminals for logs.
endlocal
