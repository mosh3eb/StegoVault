# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

# Asset data files to include
# Format: (source_path, destination_folder)
added_files = [
    ('gui/assets/*', 'gui/assets'),
    ('web/static/*', 'web/static'),
    ('web/templates/*', 'web/templates'),
]

a = Analysis(
    ['gui_launcher.py'],
    pathex=[],
    binaries=[],
    datas=added_files,
    hiddenimports=['PIL._tkinter_finder', 'PyQt6.sip'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='StegoVault',
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
    icon='gui/assets/logo.png' # PyInstaller will convert this to .ico on Windows automatically if possible, or we use .png
)

