"""This file contains helper routines that make use of LIEF primitives."""

import lief

import subprocess
import os

from typing import List

from misc.plist import parse_resilient_bytes

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
    """
    Returns the contents of the section containing the Info.plist, iff such a section exists.
    Single-file tools or libraries (for example, libswift* dylibs) frequently contain such sections.
    :param binary: LIEF binary object from which to extract section
    :return: Dictionary of embedded Info.plist section or None
    """
    for sect in binary.sections:
        if sect.name == "__info_plist":
            contents = bytes(sect.content)
            return parse_resilient_bytes(contents)

    return None


def resolve_library_path(path: str,
                         rpaths: List[str],
                         loader_path: str,
                         executable_path: str) -> str:
    """
    Attempts to resolve library path to an actual location on the filesystem.
    :param path: The library path to resolve. Library paths can contain placeholders such
                 as @loader_path, @executable_path and @rpath, which are replaced and
                 resolved by this function.
    :param rpaths: List of concrete rpath replacements to try.
    :param loader_path: @loader_path replacement
    :param executable_path: @executable_path replacement
    :return: Concrete filesystem path, in case the library could be resolved
    :raises ValueError, if library path cannot be resolved
    """
    # Replace @loader_path and @executable_path
    path = path.replace("@loader_path", loader_path, 1)
    path = path.replace("@executable_path", executable_path, 1)

    # Check for @rpath and handle @rpath
    if not "@rpath" in path:
        return os.path.realpath(path)

    # Attempt each @rpath replacement candidate, return first result
    # that actually exists (or raise ValueError if no such rpath)
    for rpath in rpaths:
        new_path = path.replace("@rpath", rpath, 1)
        if os.path.exists(new_path):
            return os.path.realpath(new_path)
    else:
        raise ValueError("Library location could not be determined.")


def extract_rpaths(binary,
                   loader_path: str,
                   executable_path: str) -> List[str]:
    """
    Extracts @rpath commands from a binary and returns a list of paths encountered.
    :param binary: The binary from which to extract the rpath commands
    :param loader_path: @loader_path replacement
    :param executable_path: @executable_path replacement
    :return: List of rpath replacements (possible values for @rpath)
    """
    # There is a number of default paths
    rpaths = RPATH_DEFAULT_PATHS.copy()

    for cmd in binary.commands:
        if isinstance(cmd, lief.MachO.RPathCommand):
            rpath = cmd.path
            # rpaths can contain @executable_path and @loader_path, also
            rpath = rpath.replace("@loader_path", loader_path, 1)
            rpath = rpath.replace("@executable_path", executable_path, 1)

            rpaths.append(rpath)

    return rpaths


def load_cmd_is_weak(lc) -> bool:
    """
    Checks whether the load command `lc` is a LC_LOAD_WEAK_DYLIB command
    that is allowed to fail. Unfortunately, this is not yet part of LIEF.

    :param lc: The LIEF load command to check
    :return: True, if the load command is LC_LOAD_WEAK_DYLIB
    """
    raw_data = lc.data
    # 0x18 is the identifier for LC_LOAD_WEAK_DYLIB
    return raw_data[0] == 0x18


def imported_symbols(bin_path: str) -> List[str]:
    """
    Compute the imported symbols for a binary. Currently uses the nm command line
    tool and parses its output, as this is significantly faster for large files than using
    lief and its built-in functionality
    :param bin_path: Path to binary
    :return: List of external symbols imported.
    """
    # Execute the nm process
    cmd = ["/usr/bin/nm",
           "-g", # Display only global (external) symbols
           "-j", # Display the symbol only, eases parsing for us
           bin_path]

    try:
        output = subprocess.check_output(cmd, stderr = subprocess.DEVNULL)
        return [x.decode(encoding='utf8') for x in output.splitlines()]
    except subprocess.CalledProcessError:
        # On error, simply return empty results
        return []