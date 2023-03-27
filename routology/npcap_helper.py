def install_npcap():
    import subprocess
    import os
    import sys

    def resource_path(relative_path):
        """Get absolute path to resource, works for dev and for PyInstaller"""
        base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base_path, relative_path)

    # Bundled 1.72 version
    proc = subprocess.run("npcap.exe", shell=True, cwd=resource_path("vendor"))
    proc.check_returncode()
