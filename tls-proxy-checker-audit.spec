# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ["src/tls_proxy_checker/cli.py"],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        "rich",
        "OpenSSL",
        "cryptography",
        "tls_proxy_checker.profiles",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
a.binaries = [entry for entry in a.binaries if entry[0] != "libgcc_s.so.1"]
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="tls-proxy-checker-audit",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    name="tls-proxy-checker-audit",
)
