from extractors.base import AbstractExtractor, ResultCount
from bundle.bundle import Bundle
from bundle.application import Application
import misc.filesystem as fs
import binary.common

import os.path
import lief
import json


class DependenciesExtractor(AbstractExtractor):
    """Extracts the direct dependencies of an application

    Dependencies / Loaded libraries and frameworks run inside the same
    sandbox as the main executable. Therefore, permissions / entitlements
    are irrelevant. This information is stored, mainly to be able to check
    for outdated libraries.

    The information is stored as JSON in the file dependencies.json. Each
    entry contains the dependency's filename, and, if available,
    the corresponding bundle-id, as well its version number.
    If the corresponding bundle could not be found, attempts are made to extract
    the Info.plist from the binary itself. If that also fails, only the path
    for the dependency is recorded.
    """
    @classmethod
    def resource_type(cls):
        return "dependencies"

    @classmethod
    def result_count(cls):
        # The result is just a single JSON file listing the dependencies
        return ResultCount.SINGLE

    @staticmethod
    def _extract_dependency_infos(info):
        """Extracts the required keys (CFBundleIdentifier and CFBundleShortVersionString / CFBundleVersion)
        from the info.plist supplied as a dictionary to this method.

        In case only a subset of this information is provided, only a subset is returned"""
        assert(isinstance(info, dict))

        result = dict()
        if "CFBundleIdentifier" in info:
            result["CFBundleIdentifier"] = info["CFBundleIdentifier"]

        if "CFBundleShortVersionString" in info:
            result["CFBundleShortVersionString"] = info["CFBundleShortVersionString"]
        elif "CFBundleVersion" in info:
            result["CFBundleVersion"] = info["CFBundleVersion"]

        return result

    def extract_data(self, app: Bundle, result_path: str) -> bool:
        # Metadata is stored in a dictionary, which is later serialised to the disk.
        dependencies_metadata = dict()

        if not isinstance(app, Application):
            self.log_error("Supplied app {} is not an application".format(app.filepath))
            return False

        app_dependencies = app.executable().application_libraries()
        for dependency in app_dependencies:
            dependency_bundle = Bundle.from_binary(dependency)
            # Relative path component from the underlying app to the dependency.
            dependency_rel = fs.path_remove_prefix(dependency, app.filepath + "/")

            dependency_infos = None

            if dependency_bundle:
                # Use Info.plist from bundle
                dependency_infos = dependency_bundle.info_dictionary()
            else:
                # Try to instead use embedded information
                # Note: extract_embedded_info returns None on failure
                dependency_infos = binary.common.extract_embedded_info(
                    lief.parse(dependency)
                )

            if dependency_infos:
                # Record entry along with further information
                dependencies_metadata[dependency_rel] = DependenciesExtractor._extract_dependency_infos(dependency_infos)
            else:
                # Just record the path to the dependency
                dependencies_metadata[dependency_rel] = {}

        # Store the information to the filesystem
        with open(os.path.join(result_path, "dependencies.json"), "w") as outfile:
            json.dump(dependencies_metadata, outfile, indent=4)

        return True
