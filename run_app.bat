@echo off
echo Installing dependencies...
pip install -r requirements.txt
echo.
echo Starting Idle Time Tracker...
python app.py
pause
