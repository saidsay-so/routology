import subprocess
import sys
import os

specfile = sys.argv[1] if len(sys.argv) > 1 else "routology.spec"

match os.name:
    case "nt":
        args = ["--uac-admin"]
    case _:
        args = []

sub = subprocess.run(["pyinstaller", *args, specfile])

sub.check_returncode()
