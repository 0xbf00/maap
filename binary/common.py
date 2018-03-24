"""This file contains helper routines that make use of LIEF primitives."""

import lief
import plistlib

from bundle.bundle import Bundle
import misc.filesystem as fs
import subprocess

import os.path

from typing import List

RPATH_DEFAULT_PATHS = [
    "/usr/lib",  # The MathViz.app bundle contains a load instruction
    # referencing @rpath/libobjc.A.dylib, which the linker
    # resolves to /usr/lib/libobjc.A.dylib, despite there
    # not being a corresponding @rpath command. Checking
    # out the dyld sources, a few standard paths become
    # apparent (DYLD_FALLBACK_LIBRARY_PATH)
    "/usr/local/lib",
    "/lib",
    os.path.join(os.path.expanduser("~"), "lib")
]


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

    rpaths = RPATH_DEFAULT_PATHS.copy()

    for cmd in binary.commands:
        if isinstance(cmd, lief.MachO.RPathCommand):
            rpath = cmd.path
            # rpaths can contain @executable_path and @loader_path, also
            rpath = rpath.replace("@loader_path", loader_path, 1)
            rpath = rpath.replace("@executable_path", executable_path, 1)

            rpaths.append(rpath)

    return rpaths


def bundle_from_binary(bin_path : str) -> Bundle:
    """Finds the bundle that contains a specific binary.

    Throws a ValueError if the supplied binary is
        a) not a binary
        b) does not exist

    Returns
        On success: The bundle
        On failure: None
    """
    # Binary has to be valid
    if not (os.path.exists(bin_path) and lief.is_macho(bin_path)):
        raise ValueError("Invalid executable specified")

    containing_dir = os.path.dirname(bin_path)
    while containing_dir != "/":
        # Potential bundle found
        if Bundle.is_bundle(containing_dir):
            bun = Bundle.make(containing_dir)
            if not os.path.isfile(bun.executable_path()):
                # File specified in Info.plist does not exist.
                # This sometimes happens for applications with incorrectly
                # configured frameworks. In these cases, as a workaround,
                # we simply check whether the filepath of the current bundle
                # is contained in the `bin_path`.
                if os.path.commonpath([bun.filepath, bin_path]) == bun.filepath:
                    return bun
            elif fs.is_same_file(bun.executable_path(), bin_path):
                return bun

        # Move up one level
        containing_dir = os.path.dirname(containing_dir)

    return None


def load_cmd_is_weak(lc) -> bool:
    """Checks whether the load command `lc` is a LC_LOAD_WEAK_DYLIB command
    that is allowed to fail

    Unfortunately, so far, lief does not support this out of the box."""
    raw_data = lc.data
    # 0x18 is the identifier for LC_LOAD_WEAK_DYLIB
    return raw_data[0] == 0x18


def imported_symbols(bin_path : str) -> List[str]:
    """Compute the imported symbols for a binary. Currently uses the nm command line
    tool and parses its output, as this is significantly faster for large files than using
    lief and its built-in functionality"""

    # Execute the nm process
    cmd = ["/usr/bin/nm",
           "-g", # Display only global (external) symbols
           "-j", # Display the symbol only, eases parsing for us
           bin_path]

    try:
        output = subprocess.check_output(cmd, stderr = subprocess.DEVNULL)
        result = list(map(lambda x: x.decode(encoding = "utf8"),
                          output.splitlines()))
        return result
    except subprocess.CalledProcessError:
        # On error, simply return empty results
        return []