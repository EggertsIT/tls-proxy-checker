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
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
# Preserve the manylinux wheel's portability by using the target system's
# libgcc_s instead of bundling the build host's newer runtime.
a.binaries = [entry for entry in a.binaries if entry[0] != "libgcc_s.so.1"]
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="tls-proxy-checker",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
