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
    entry contains the dependency's filename, the corresponding bundle-id,
    as well its version number. If the corresponding bundle could not be found,
    attempts are made to extract the Info.plist from the binary itself.
    If that also fails, the information regarding this dependency is thrown out
    (Because single dylibs contain little information of interest, and these are the
    only files that should fail)
    """
    @classmethod
    def resource_type(cls):
        return "dependencies"

    @classmethod
    def result_count(cls):
        # The result is just a single JSON file listing the dependencies
        return ResultCount.SINGLE

    def _info_extract_required(self, info):
        """Extracts the required keys (CFBundleIdentifier and CFBundleShortVersionString)
        from the info.plist supplied as a dictionary to this method.

        Returns None in case the information could not be extracted, otherwise returns
        a dictionary containing the two aforementioned keys."""
        assert(isinstance(info, dict))

        if not (
            "CFBundleIdentifier" in info and
            ("CFBundleShortVersionString" in info or "CFBundleVersion" in info) # Some plists only contain one of them
        ):
            return None

        result = {
            "CFBundleIdentifier": info["CFBundleIdentifier"]
        }
        if "CFBundleShortVersionString" in info:
            result["CFBundleShortVersionString"] = info["CFBundleShortVersionString"]
        else:
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
            dependency_bundle = binary.common.bundle_from_binary(dependency)
            # Relative path component from the underlying app to the dependency.
            dependency_rel = fs.path_remove_prefix(dependency, app.filepath + "/")

            if not dependency_bundle:
                if dependency.endswith(".dylib"):
                    # Dylib's can contain an Info.plist file embedded in them!
                    # Try to extract this information as a fallback
                    embedded_info = binary.common.extract_embedded_info(
                        lief.parse(dependency)
                    )
                    if embedded_info:
                        required_info = self._info_extract_required(embedded_info)
                        if not required_info:
                            self.log_error(
                                "Embedded Info.plist found for dependency {} of application {}, but required keys were not present".format(
                                    dependency,
                                    app.filepath
                                )
                            )
                            # It is considered a violation if the Info.plist was extracted but did not contain the
                            # required keys.
                            return False
                        else:
                            dependencies_metadata[dependency_rel] = required_info
                    else:
                        self.log_info("Found DYLIB dependency {} for application {}, ignored because lacking Info.plist".format(
                            dependency, app.filepath
                        ))
                        # Also record simple .dylibs.
                        dependencies_metadata[dependency_rel] = {}
                        continue
                else:
                    self.log_error("Unable to find bundle for dependency {} of app {}".format(
                        dependency, app.filepath))
                    return False
            else:
                required_info = self._info_extract_required(dependency_bundle.info_dictionary())
                if not required_info:
                    self.log_error("Info.plist found for dependency {} of app {} does not contain required keys.".format(
                        dependency, app.filepath
                    ))
                    return False

                dependencies_metadata[dependency_rel] = required_info

        # Store the information to the filesystem
        with open(os.path.join(result_path, "dependencies.json"), "w") as outfile:
            json.dump(dependencies_metadata, outfile, indent=4)

        return True
