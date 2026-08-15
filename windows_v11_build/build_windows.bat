@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo Soundvision to DXF converter v11 - Windows build
echo ============================================================

where py >nul 2>&1
if errorlevel 1 (
  echo ERROR: Python launcher 'py' not found.
  echo Install Python 3.11 or newer from python.org and try again.
  pause
  exit /b 1
)

if exist .venv rmdir /s /q .venv
py -3 -m venv .venv
if errorlevel 1 goto :fail
call .venv\Scripts\activate.bat

python -m pip install --upgrade pip
if errorlevel 1 goto :fail
pip install ezdxf cryptography pyinstaller
if errorlevel 1 goto :fail

python self_test.py
if errorlevel 1 (
  echo.
  echo SELF-TEST FAILED. The EXE will NOT be built.
  goto :fail
)

pyinstaller --noconfirm --clean --onefile --windowed ^
  --name "Soundvision to DXF converter" ^
  --icon "icon.ico" ^
  --hidden-import cryptography ^
  --collect-all ezdxf ^
  windows_app.py
if errorlevel 1 goto :fail

echo Running self-test on the built Windows EXE...
"dist\Soundvision to DXF converter.exe" --self-test
if errorlevel 1 (
  echo.
  echo BUILT EXE SELF-TEST FAILED.
  goto :fail
)

echo.
echo ============================================================
echo BUILD SUCCESSFUL
echo ============================================================
echo EXE: dist\Soundvision to DXF converter.exe
echo.
pause
exit /b 0

:fail
echo.
echo BUILD FAILED.
pause
exit /b 1
