# Console onefile; no recursive project/data collection or runtime safety changes.
from pathlib import Path
from PyInstaller.utils.hooks import copy_metadata

ROOT = Path(SPECPATH).resolve().parent
# Textual widgets are lazily imported through __getattr__. Include the widgets
# used by MacTrim and Textual's supporting tab/help/loading/tooltip components.
WIDGETS = ('button', 'content_switcher', 'data_table', 'footer', 'header',
           'help_panel', 'input', 'key_panel', 'label', 'loading_indicator',
           'option_list', 'progress_bar', 'select', 'static', 'tabbed_content',
           'tabs', 'tooltip')
a = Analysis(
    [str(ROOT / 'bundle' / 'entry.py')],
    pathex=[str(ROOT)],
    binaries=[],
    datas=copy_metadata('textual') + copy_metadata('rich'),
    hiddenimports=['mactrim.ui'] + ['textual.widgets._' + name for name in WIDGETS],
    hookspath=[], hooksconfig={}, runtime_hooks=[],
    excludes=['tests', 'unittest', 'pytest', 'pip', 'setuptools', 'tkinter'],
    noarchive=False, optimize=0,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name='mactrim', debug=False, bootloader_ignore_signals=False,
    strip=False, upx=False, console=True,
    disable_windowed_traceback=False,
    argv_emulation=False, target_arch='arm64',
    codesign_identity=None, entitlements_file=None,
    runtime_tmpdir=None,
)
