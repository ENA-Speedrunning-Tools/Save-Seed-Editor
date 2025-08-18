from cx_Freeze import setup, Executable
import sys
import os

script_name = "ENA_Seed_Editor.py"

include_files = ["ena_dbbq.png", "config.ini"]

build_exe_options = {
    "packages": ["os", "sys", "tkinter", "Crypto", "keyboard", "configparser", "json", "datetime"],
    "include_files": include_files,
    "includes": ["tkinter.ttk", "tkinter.filedialog"],
    "excludes": [],
    "optimize": 2,
    "build_exe": "build_dist"
}

base = "Win32GUI"

setup(
    name="ENA_Seed_Editor",
    version="1.0.0",
    description="ENA: Dream BBQ / Seed Editor",
    options={"build_exe": build_exe_options},
    executables=[Executable(script_name, base=base, icon="ena_dbbq.ico")],
)