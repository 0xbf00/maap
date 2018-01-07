"""This file contains helper routines that make use of LIEF primitives."""

import lief
import plistlib

import os.path

from typing import List


def extract_embedded_info(binary) -> dict:
    """Returns the contents of the section
    containing the Info.plist, iff such a
    section exists. Single-file libraries
    (for example libswift* dylibs) frequently
    contain such sections."""
    for sect in binary.sections:
        if sect.name == "__info_plist":
            contents = bytes(sect.content)
            plist = plistlib.loads(contents)

            return plist

    return None


def resolve_library_path(path: str,
                         rpaths: List[str],
                         loader_path: str,
                         executable_path: str) -> str:
    """Replaces @executable_path and @loader_path.
    Tries a number of different rpaths and returns the one
    that results in a valid file being referenced. Throws an exception
    if no such file was found."""

    # Replace @loader_path and @executable_path
    path = path.replace("@loader_path", loader_path, 1)
    path = path.replace("@executable_path", executable_path, 1)

    # Check for @rpath and handle @rpath
    if not "@rpath" in path:
        return os.path.realpath(path)

    for rpath in rpaths:
        new_path = path.replace("@rpath", rpath, 1)
        if os.path.exists(new_path):
            return os.path.realpath(new_path)
    else:
        raise ValueError("Library location could not be determined.")


def extract_rpaths(binary,
                   loader_path: str,
                   executable_path: str) -> List[str]:
    """Extracts @rpath commands from a binary and returns the list
    of paths encountered."""

    rpaths = []

    for cmd in binary.commands:
        if isinstance(cmd, lief.MachO.RPathCommand):
            rpath = cmd.path
            # rpaths can contain @executable_path and @loader_path, also
            rpath = rpath.replace("@loader_path", loader_path, 1)
            rpath = rpath.replace("@executable_path", executable_path, 1)

            rpaths.append(rpath)

    return rpaths
