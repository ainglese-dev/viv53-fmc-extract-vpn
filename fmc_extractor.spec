import importlib.metadata
import os
import streamlit

streamlit_dir = os.path.dirname(streamlit.__file__)
streamlit_distinfo = str(importlib.metadata.distribution("streamlit")._path)

block_cipher = None

a = Analysis(
    ["run_app.py"],
    pathex=["."],
    binaries=[],
    datas=[
        ("app.py", "."),
        ("web", "web"),
        ("configs", "configs"),
        (os.path.join(streamlit_dir, "static"),    "streamlit/static"),
        (os.path.join(streamlit_dir, "runtime"),   "streamlit/runtime"),
        (os.path.join(streamlit_dir, "web"),        "streamlit/web"),
        (os.path.join(streamlit_dir, "proto"),      "streamlit/proto"),
        (os.path.join(streamlit_dir, "vendor"),     "streamlit/vendor"),
        (streamlit_distinfo, "streamlit-1.50.0.dist-info"),
    ],
    hiddenimports=[
        "streamlit",
        "streamlit.web.cli",
        "streamlit.web.server",
        "streamlit.web.server.server",
        "streamlit.runtime",
        "streamlit.runtime.scriptrunner",
        "streamlit.runtime.scriptrunner.magic_funcs",
        "streamlit.components.v1",
        "web.extractor",
        "web.bundler",
        # Streamlit runtime deps
        "altair",
        "pyarrow",
        "pydeck",
        "click",
        "tornado",
        "packaging",
        "PIL",
        "attr",
        "toolz",
        "gitpython",
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

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="FMC VPN Extractor",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    name="FMC VPN Extractor",
)

app = BUNDLE(
    coll,
    name="FMC VPN Extractor.app",
    icon=None,
    bundle_identifier="com.fmc.vpnextractor",
    info_plist={
        "CFBundleShortVersionString": "1.0.0",
        "CFBundleDisplayName": "FMC VPN Extractor",
        "NSHighResolutionCapable": True,
    },
)
