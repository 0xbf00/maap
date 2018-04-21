"""The Plist module assists in Plist (propertly list) parsing. Even though
the `plistlib` module exists, it fails to parse some files that are malformed
and choke up the XML parser, while being accepted by macOS. This module
bridges the gap and attempts to accept all plists that are accepted by macOS."""

import os.path
import tempfile
import subprocess
import plistlib
from misc.filesystem import project_path

SANITIZER_PATH = project_path("mas_tools/extern/plist_sanitizer")
assert(os.path.exists(SANITIZER_PATH))


def parse_resilient(filepath : str) -> dict:
    """Parse a PLIST file.

    Compared to plistlib's functionality, this function tries to recover on error.
    plistlib sometimes fails due to slightly malformed XML, even though macOS reads
    such failing files without a problem."""

    if not os.path.exists(filepath):
        raise ValueError("File does not exist.")

    try:
        with open(filepath, "rb") as plistFile:
            return plistlib.load(plistFile)
    except:
        with tempfile.TemporaryDirectory() as tempdir:
            tempfile_out = os.path.join(tempdir, "Info-new.plist")
            return_value = subprocess.run([SANITIZER_PATH, filepath, tempfile_out],
                                          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL)
            if return_value.returncode != 0:
                raise ValueError("Unable to correct PLIST file.")

            with open(tempfile_out, "rb") as outfile:
                try:
                    return plistlib.load(outfile)
                except:
                    raise ValueError("Unable to parse PLIST file.")
