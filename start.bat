@echo off
title PQCrypt Sentinel Launcher
echo ===================================================
echo   PQCrypt Sentinel Startup Script
echo ===================================================
echo.
echo Launching services in a single minimized Windows Terminal:
echo  1. Backend API Server (Uvicorn on Port 8000)
echo  2. Celery Worker Pool ( solo )
echo  3. Frontend Development Server (Vite)
echo.
echo Please wait, starting minimized terminal...
echo.

start /min wt new-tab --title "Backend API" -d "%~dp0backend" cmd /k "set SECRET_KEY=f4e2f92b2d7d94de29b3358ed12dc3f23b96d2e711876e0a6d27e6b596aa163a && .venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000" ^; new-tab --title "Celery Worker" -d "%~dp0backend" cmd /k "set SECRET_KEY=f4e2f92b2d7d94de29b3358ed12dc3f23b96d2e711876e0a6d27e6b596aa163a && .venv\Scripts\python.exe -m celery -A app.celery_app worker --loglevel=info -P solo" ^; new-tab --title "Frontend Dev" -d "%~dp0frontend" cmd /k npm run dev

echo Startup complete. You can close this window.
timeout /t 3 >nul
