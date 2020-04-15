import lief

from .common import extract_rpaths, resolve_library_path, load_cmd_is_weak
from .lief_extensions import macho_parse_quick

import os
import subprocess
import tempfile

from misc import plist
from misc.logger import create_logger
from extern.tools import tool_named

logger = create_logger('binary')


class Binary:
    """
    Wrapper class around lief binary object. Supports extracting libraries for an application
    and allows extracting entitlements from binary. Note that lief is rather slow when parsing
    binaries. Therefore, some operations are implemented as static methods and do not use lief.
    """
    def __init__(self, filepath, loader_path = None, executable_path = None):
        try:
            if not lief.is_macho(filepath):
                raise ValueError("Executable has wrong format")
            self.filepath = filepath
            self.containing_folder = os.path.dirname(filepath)
            self.parsed_binary = macho_parse_quick(filepath)

            # For more information about @loader_path and @executable_path,
            # check out https://www.mikeash.com/pyblog/friday-qa-2009-11-06-linking-and-install-names.html
            self.loader_path = loader_path if loader_path else self.containing_folder
            self.executable_path = executable_path if executable_path else self.containing_folder

        except lief.bad_file:
            raise ValueError("Executable not found")

    @classmethod
    def get_entitlements(cls, filepath, raw = False):
        """
        Extract entitlements from a target binary.

        :param filepath: filepath for binary for which to extract entitlements
        :param raw: Whether to return the raw bytes. If false, returns a dictionary. Else, returns bytes
        :return: Dictionary containing application entitlements. Returns empty dictionary
                 in case of errors.
        """
        jtool = tool_named("jtool")

        env = os.environ.copy()
        env['ARCH'] = 'x86_64'

        exit_code, results = jtool("--ent", filepath, env=env)
        if exit_code != 0:
            return dict()
        
        if raw:
            return results
        else:
            return plist.parse_resilient_bytes(results)

    def application_libraries(self):
        """
        Return only linked libraries that are shipped as part of the application bundle.
        Note that this still might contain Apple libraries, because for instance Swift libraries
        are shipped as part of an app.
        :return: List of application libraries
        """
        all_libraries = self.linked_libraries()

        application_path = self.containing_folder
        if application_path.endswith("/Contents/MacOS"):
            application_path = application_path[:-len("/Contents/MacOS")]

        return [ x for x in all_libraries if x.startswith(application_path) and x != self.filepath ]

    def linked_libraries(self):
        """
        Return resolved list of linked libraries for a given binary.

        :return: List of linked libraries.
        :raise ValueError, if library cannot be resolved.
        """
        assert self.parsed_binary

        linked_libs = list(self.parsed_binary.libraries)
        rpaths = extract_rpaths(self.parsed_binary, self.loader_path, self.executable_path)

        resolved_libs = []
        for lib in linked_libs:
            if load_cmd_is_weak(lib):
                # Weak load commands are allowed to fail!
                try:
                    resolved_lib = resolve_library_path(lib.name,
                                                        rpaths,
                                                        self.loader_path,
                                                        self.executable_path)
                    if not os.path.exists(resolved_lib):
                        logger.info('Weak load command resolved to {}, which does not exist.'.format(resolved_lib))
                    else:
                        resolved_libs.append(resolved_lib)
                except ValueError:
                    continue
            else:
                resolved_lib = resolve_library_path(lib.name,
                                                    rpaths,
                                                    self.loader_path,
                                                    self.executable_path)
                if not os.path.exists(resolved_lib):
                    logger.error('Load command resolved to {}, which does not exist.'.format(resolved_lib))
                else:
                    resolved_libs.append(resolved_lib)

        return resolved_libs
