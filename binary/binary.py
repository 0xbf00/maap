import lief

from binary.common import extract_rpaths, resolve_library_path

import os.path


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

        linked_libs = [lib.name for lib in self.parsed_binary.libraries]
        rpaths = extract_rpaths(self.parsed_binary, self.loader_path, self.executable_path)
        linked_libs = [resolve_library_path(lib,
                                            rpaths,
                                            self.loader_path,
                                            self.executable_path)
                       for lib in linked_libs]

        return linked_libs
