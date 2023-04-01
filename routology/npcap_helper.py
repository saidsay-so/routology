def install_npcap():
    import subprocess
    import os
    import sys
    from pathlib import Path

    def resource_path(relative_path):
        """Get absolute path to resource, works for dev and for PyInstaller"""
        fallback_path = Path(os.path.dirname(os.path.abspath(__file__))).parent
        base_path = getattr(sys, "_MEIPASS", fallback_path)
        return os.path.join(base_path, relative_path)

    # Bundled 1.72 version
    proc = subprocess.run("npcap.exe", shell=True, cwd=resource_path("vendor"))
    proc.check_returncode()
