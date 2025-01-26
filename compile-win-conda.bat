@echo off

REM Define the name of the conda environment
SET ENV_NAME=cipher

REM Check if the conda environment exists
conda env list | findstr /C:"%ENV_NAME%" >nul
IF ERRORLEVEL 1 (
    ECHO Creating conda environment '%ENV_NAME%'...
    REM Create the conda environment with the specified Python version
    conda create -y -n %ENV_NAME% python=3.10

    echo Conda environment '%ENV_NAME%' created.
    echo Please rerun the script to compile the application.
    pause
)

REM Activate the conda environment
CALL conda activate %ENV_NAME%

REM Install the required packages in the conda environment
pip install -e .

REM Install pyinstaller in the conda environment
pip install pyinstaller

REM Run pyinstaller with your spec file
pyinstaller gui_win.spec


pause