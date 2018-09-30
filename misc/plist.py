"""The Plist module assists in Plist (propertly list) parsing. Even though
the `plistlib` module exists, it fails to parse some files that are malformed
and choke up the XML parser, while being accepted by macOS. This module
bridges the gap and attempts to accept all plists that are accepted by macOS."""

import os
import tempfile
import subprocess
import plistlib
from extern.tools import tool_named

SANITIZER = tool_named("plist_sanitizer")


def parse_resilient_bytes(b: bytes) -> dict:
    """
    Parses a bytes object representing a PLIST file.
    :param b: Bytes object to parse
    :return: Parsed dictionary.
    :raises ValueError on failure
    """
    with tempfile.NamedTemporaryFile(mode='wb') as outfile:
        outfile.write(b)
        outfile.flush()

        return parse_resilient(outfile.name)


def parse_resilient(filepath: str) -> dict:
    """
    Parses a plist object from disk.
    :param filepath: Filepath to PLIST to parse
    :return: Parsed dictionary
    :raises ValueError on failure
    """
    if not os.path.exists(filepath):
        raise ValueError("File does not exist.")

    try:
        with open(filepath, "rb") as plistFile:
            return plistlib.load(plistFile)
    except:
        with tempfile.TemporaryDirectory() as tempdir:
            tempfile_out = os.path.join(tempdir, "Info-new.plist")
            return_value = subprocess.run([SANITIZER, filepath, tempfile_out],
                                          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL)
            if return_value.returncode != 0:
                raise ValueError("Unable to correct PLIST file.")

            with open(tempfile_out, "rb") as outfile:
                try:
                    return plistlib.load(outfile)
                except:
                    raise ValueError("Unable to parse PLIST file.")
