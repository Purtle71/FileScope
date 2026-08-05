# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

block_cipher = None

datas = [("rules", "rules"), ("assets", "assets")]
binaries = []
hiddenimports = [
    "pefile",
    "PIL.Image",
    "pypdf",
    "yara_x",
    "androguard.core.axml",
    "androguard.core.axml.types",
    "androguard.core.dex",
    "androguard.core.dex.dex_types",
    "androguard.core.apk",
    "androguard.core.bytecode",
    "androguard.core.mutf8",
    "androguard.core.androconf",
    "apkInspector",
    "asn1crypto",
    "cryptography",
    "cryptography.hazmat.bindings._rust",
    "lxml.etree",
    "mutf8",
    "win32_setctime",
]

for package in ("yara_x",):
    package_datas, package_binaries, package_hidden = collect_all(package)
    datas += package_datas
    binaries += package_binaries
    hiddenimports += package_hidden

a = Analysis(
    ["app.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "IPython",
        "dataset",
        "sqlalchemy",
        "alembic",
        "networkx",
        "pydot",
        "yaml",
        "matplotlib",
        "tkinter",
    ],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="FileScope",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=["assets/filescope.ico"],
)
