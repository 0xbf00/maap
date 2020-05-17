"""The Plist module assists in Plist (propertly list) parsing. Even though
the `plistlib` module exists, it fails to parse some files that are malformed
and choke up the XML parser, while being accepted by macOS. This module
bridges the gap and attempts to accept all plists that are accepted by macOS."""

import os
import subprocess
import plistlib


class tdict(dict):
    """
    Typed dict extension.
    """
    def typed_get(self, key, type, default=None):
        """
        Return the value for `key` if key is in the dictionary and is of type `type`,
        else return `default`.
        """
        if key not in self:
            return default

        if not isinstance(self[key], type):
            return default

        return self[key]


def parse_resilient_bytes(b: bytes) -> dict:
    """
    Parses a bytes object representing a PLIST file.
    :param b: Bytes object to parse
    :return: Parsed dictionary.
    :raises ValueError on failure
    """
    try:
        return tdict(plistlib.loads(b))
    except:
        plutil = subprocess.run(
            ['plutil' '-convert', 'xml1', '-o', '/dev/stdout', '-'],
            check=True,
            capture_output=True,
            input=b,
        )
        try:
            return tdict(plistlib.loads(plutil.stdout.decode()))
        except:
            raise ValueError("Unable to parse PLIST file.")


def parse_resilient(filepath: str) -> dict:
    """
    Parses a plist object from disk.
    :param filepath: Filepath to PLIST to parse
    :return: Parsed dictionary
    :raises ValueError on failure
    """
    if not os.path.exists(filepath):
        raise ValueError("File does not exist.")

    with open(filepath, "rb") as plistFile:
        content = plistFile.read()
        if not content.startswith(b'bplist'):
            content = content.strip()
        return parse_resilient_bytes(content)