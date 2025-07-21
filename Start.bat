@echo off
REM This script sets up and runs the Packet Sniffer application.

echo [INFO] Checking for Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not found in your PATH. Please install Python and add it to your PATH.
    pause
    exit /b
)

echo [INFO] Setting up virtual environment...
if not exist ".venv" (
    python -m venv .venv
)

echo [INFO] Activating virtual environment...
call .venv\Scripts\activate.bat

echo [INFO] Installing dependencies from requirements.txt...
pip install -r requirements.txt

echo [INFO] Launching the Packet Sniffer Dashboard...
echo [INFO] You may need to run this script as an Administrator to capture packets.
streamlit run Sniffer.py

echo [INFO] Application closed.
pause
