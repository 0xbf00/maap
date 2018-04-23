import lief

from binary.common import extract_rpaths, resolve_library_path, load_cmd_is_weak

import os
import subprocess
import tempfile

from misc import plist
from misc.logger import create_logger

logger = create_logger('binary')


class Binary:
    def __init__(self, filepath, loader_path = None, executable_path = None):
        try:
            if not lief.is_macho(filepath):
                raise ValueError("Executable has wrong format")
            self.filepath = filepath
            self.containing_folder = os.path.dirname(filepath)
            self.parsed_binary = lief.parse(filepath)

            # For more information about @loader_path and @executable_path,
            # check out https://www.mikeash.com/pyblog/friday-qa-2009-11-06-linking-and-install-names.html
            self.loader_path = loader_path if loader_path else self.containing_folder
            self.executable_path = executable_path if executable_path else self.containing_folder

        except lief.bad_file:
            raise ValueError("Executable not found")

    @classmethod
    def get_entitlements(cls, filepath, raw = False):
        """
        Uses jtool to extract the entitlements from a target binary.
        Returns an empty dictionary if no entitlements were found or an error occurred.
        If the caller requests raw entitlements, returns a bytestring of the entitlements!
        """
        JTOOL_PATH = os.path.join(os.path.dirname(__file__), "../extern/jtool")
        assert (os.path.exists(JTOOL_PATH))

        with tempfile.NamedTemporaryFile() as ent_file:
            env = os.environ.copy()
            env["ARCH"] = "x86_64"

            return_value = subprocess.run([JTOOL_PATH, "--ent", filepath],
                                      stdin=subprocess.DEVNULL, stdout=ent_file,
                                      stderr=subprocess.DEVNULL, env = env)

            if return_value.returncode != 0:
                return dict()
            else:
                if raw:
                    # Return raw bytes to caller.
                    ent_file.seek(0)
                    return ent_file.read()

                return plist.parse_resilient(ent_file.name)

    def application_libraries(self):
        """Return only the libraries / frameworks that are shipped as part of the
        application bundle.

        Note that this still might contain Apple libraries, because
        for example the Swift libraries are shipped as part of an app.
        """

        all_libraries = self.linked_libraries()

        application_path = self.containing_folder
        if application_path.endswith("/Contents/MacOS"):
            application_path = application_path[:-len("/Contents/MacOS")]

        return list(filter(lambda x: x.startswith(application_path) and x != self.filepath, all_libraries))

    def linked_libraries(self):
        assert(self.parsed_binary)

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
