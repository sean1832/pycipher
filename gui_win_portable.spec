# -*- mode: python ; coding: utf-8 -*-

import importlib.util
import os

# Load the __version__ attribute from __init__.py
spec = importlib.util.spec_from_file_location("cipher", os.path.join("cipher", "__init__.py"))
cipher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cipher)
version = cipher.__version__

a = Analysis(
    ['cipher\\gui.py'],
    pathex=['./cipher'],
    binaries=[],
    datas=[('./cipher', 'cipher')],
    hiddenimports=[
        'cipher.cipher',
        'cryptography',
        'cryptography.hazmat.primitives.kdf.pbkdf2',
        'cryptography.hazmat.primitives.kdf.scrypt',
        'cryptography.hazmat.backends.openssl.backend'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['PyQt6.QtWebEngineWidgets'],
    noarchive=True,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name=f"cipher-{version}-win-portable",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=["cipher/assets/icon.ico"],
)