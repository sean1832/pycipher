@echo off

REM Check if 'venv' directory exists
IF NOT EXIST "venv" (
    REM Create a new virtual environment named 'venv'
    python -m venv venv
)

REM Activate the virtual environment
.\venv\Scripts\activate

echo Installing the required packages...
pip install -e .

pip install pyinstaller

cls
echo.
    echo ==========================================
    echo Compiling portable version...
    echo ==========================================
    pyinstaller gui_win_portable.spec

echo.
    echo ==========================================
    echo Compiling standard version...
    echo ==========================================
    pyinstaller gui_win.spec

pause