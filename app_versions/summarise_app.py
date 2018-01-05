from Mac.Bundle import Bundle
from Helpers.Hash import sha256_file

import os
import os.path

import json
import shutil


def remove_prefix(input : str, prefix : str) -> str:
    """Removes a prefix from a string, if the string has such a prefix."""
    if input.startswith(prefix):
        return input[len(prefix):]
    return input

# TODO: Make sure to also query Little Snitch's IAPs.

def app_build_manifest(app_path : str) -> str:
    """Creates a manifest of an installed application.

    The manifest file contains the filenames, SHA256 hashes and sizes of all
    files that are part of an application bundle. Information such as UNIX permissions,
    file links and other information is not recorded. This file is not meant to be used
    to re-build an app. It's purpose is to track changes to files (did this file change?)
    and to assess the evolution in file-sizes on the Mac App Store.

    The function returns a string of serialized JSON. The string can be written to disk and
    parsed again using the json module.
    """

    app = Bundle.make(app_path)
    assert(app != None)

    hashes = dict()

    # Hash all contents of the app
    for (dirname, dirs, filenames) in os.walk(app.filepath):
        for filename in filenames:
            filepath = os.path.join(dirname, filename)
            if os.path.isfile(filepath) and not os.path.islink(filepath):
                hash = sha256_file(filepath)
                assert(hash != None)
                assert(filepath not in hashes)

                hashes[filepath] = hash

    output = []
    for key in hashes.keys():
        entry = dict()
        entry["filepath"] = remove_prefix(key, app.filepath)
        entry["filesize"] = os.path.getsize(key)
        entry["hash"]     = hashes[key]
        output.append(entry)

    # Return formatted result
    return json.dumps(output, indent = 4)


def app_build_summary(app_path : str, result_path : str) -> bool:
    """Create an archive containing the manifest, the main executable and Info.plist, along with other bundle information.

    For each bundle contained in the application, the Info.plist and executable is saved. This process is performed
    just once, so the frameworks of the frameworks for instance are not captured. This is both to save space (At this point,
    saving library / framework information is more about saving data for future work and there is no interest in retaining
    even more data.)

    The return value indicates whether the process was successful or not.
    """
    try:
        manifest = app_build_manifest(app_path)
        with open(os.path.join(result_path, "manifest.json"), "w") as manifest_file:
            manifest_file.write(manifest)

        # the `app` directory contains Info.plist and executable of the main application
        app_dir = os.path.join(result_path, "app")
        # dependencies is the folder containing all sub-bundles of an application.
        # this included other .app bundles (such as helper apps), as well as
        # general-purpose frameworks. Frameworks and other bundle treatment
        # is done by the caller.
        dep_dir = os.path.join(result_path, "dependencies")

        os.mkdir(app_dir)
        os.mkdir(dep_dir)

        app = Bundle.make(app_path)
        shutil.copy(app.executable_path(), app_dir)
        shutil.copy(app.info_dictionary_path(), app_dir)

        for bundle in app.sub_bundles():
            if not bundle:
                continue

            if not bundle.has_bundle_identifier():
                continue

            # Apple-Internal Frameworks are huge and there are lots of these, so
            # we purposefully ignore them here!
            if bundle.bundle_identifier().startswith("com.apple"):
                continue

            # Make a new directory for each bundle, by using it's bundle identifier
            # For now, we simply ignore those bundles that have no identifier
            bundle_dir = os.path.join(dep_dir, bundle.bundle_identifier())
            try:
                os.mkdir(bundle_dir)
            except FileExistsError:
                # This mainly happens when using xcode. Simply skip these occurrences.
                continue

            shutil.copy(bundle.executable_path(), bundle_dir)
            shutil.copy(bundle.info_dictionary_path(), bundle_dir)

        return True
    except:
        return False