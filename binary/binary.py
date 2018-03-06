import lief

from binary.common import extract_rpaths, resolve_library_path, load_cmd_is_weak

import os.path
import subprocess
import tempfile

from misc import plist

class Binary:
    def __init__(self, filepath, loader_path = None, executable_path = None):
        try:
            if not lief.is_macho(filepath):
                raise ValueError("Executable has wrong format")
            self.containing_folder = os.path.dirname(filepath)
            self.parsed_binary = lief.parse(filepath)

            # For more information about @loader_path and @executable_path,
            # check out https://www.mikeash.com/pyblog/friday-qa-2009-11-06-linking-and-install-names.html
            self.loader_path = loader_path if loader_path else self.containing_folder
            self.executable_path = executable_path if executable_path else self.containing_folder

        except lief.bad_file:
            raise ValueError("Executable not found")

    @classmethod
    def get_entitlements(cls, filepath) -> dict:
        """Uses jtool to extract the entitlements from a target binary.
        Returns an empty dictionary if no entitlements were found or an error occurred."""
        JTOOL_PATH = os.path.join(os.path.dirname(__file__), "../extern/jtool")
        assert (os.path.exists(JTOOL_PATH))

        with tempfile.NamedTemporaryFile() as resfile:
            # env = os.environ.copy()
            # Workaround: jtool has a bug that results in incorrect entitlement output
            # for when binary plists are used as entitlements.
            # For more details, see http://newosxbook.com/forum/viewtopic.php?f=3&t=19374
            #
            # otool still returns correct output, but unfortunately, we have to
            # remove the first 8 bytes from otool's output, because otool for some
            # reason always writes a useless header into its output, which hinders normal
            # plist decoding.
            # env["ARCH"] = "x86_64"
            #
            # return_value = subprocess.run([JTOOL_PATH, "--ent", filepath],
            #                           stdin=subprocess.DEVNULL, stdout=outfile,
            #                           stderr=subprocess.DEVNULL, env = env)
            #
            #
            # if return_value.returncode != 0:
            #     return dict()
            # else:
            #     return plist.parse_resilient(outfile.name)

            return_value = subprocess.run(["/usr/bin/codesign", "-d", "--entitlements", "-", filepath],
                                          stdin=subprocess.DEVNULL, stdout=resfile,
                                          stderr=subprocess.DEVNULL)
            assert(return_value.returncode == 0)

            resfile.seek(0)
            contents = resfile.read()

            if len(contents) <= 8:
                return dict()

            # Remove the first 8 bytes (see above)
            with tempfile.NamedTemporaryFile() as outfile:
                outfile.write(contents[8:])
                outfile.flush()

                return plist.parse_resilient(outfile.name)


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

        return list(filter(lambda x: x.startswith(application_path), all_libraries))

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
                    resolved_libs.append(resolved_lib)
                except ValueError:
                    continue
            else:
                resolved_lib = resolve_library_path(lib.name,
                                                    rpaths,
                                                    self.loader_path,
                                                    self.executable_path)
                resolved_libs.append(resolved_lib)

        return resolved_libs
