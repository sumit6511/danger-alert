@echo off
REM Builds dist\danger-alert.exe on Windows (needs Python 3.10+ on PATH).
cd /d %~dp0
python -m pip install --upgrade pyinstaller pynput || exit /b 1
python -m PyInstaller --onefile --noconsole --clean --noconfirm --name danger-alert ^
  --hidden-import pynput.keyboard._win32 --hidden-import pynput.mouse._win32 danger_alert.py
echo Built: %cd%\dist\danger-alert.exe
