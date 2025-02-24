# Build Guide
This guide will help you build the project from source.

## Build from source
### a.Using scripts
You can build the project using the provided scripts.
```bash
./compile-win.bat
```
or if you are using Conda:
```bash
./compile-win-conda.bat
```


### b.Manually using PyInstaller
You can build the project as a binary using PyInstaller.

```bash
pip install pyinstaller
pyinstaller gui_win.spec
```

You can find the built binary in the `dist` directory.

## Build for other platforms
For now, the project only supports building for Windows. You can modify the `gui_win.spec` file to build for other platforms.