from extractors.base import AbstractExtractor, ResultCount
from bundle.bundle import Bundle
from bundle.application import Application
import misc.filesystem as fs
from misc.hash import sha256_file

import os.path
import json


class ManifestExtractor(AbstractExtractor):
    """Extracts / Builds a manifest for the supplied application

    The manifest consists of one entry per file. Each entry is a dictionary
    containing as keys the filename, its SHA256 hash and its size. Information
    about links is not recorded. This file is meant to supplement other information
    and give insights into meta-information about applications, answering questions
    such as What is the average grow in size of applications? What is the relation
    between size of the executable and size of the overall application bundle?

    The information is encoded as a JSON file with the name manifest.json
    """
    @classmethod
    def resource_type(cls):
        return "manifest"

    @classmethod
    def result_count(cls):
        return ResultCount.SINGLE

    def _build_manifest(self, app) -> list:
        hashes = dict()

        # Hash all contents of the app
        for (dirname, dirs, filenames) in os.walk(app.filepath):
            for filename in filenames:
                filepath = os.path.join(dirname, filename)
                if os.path.isfile(filepath) and not os.path.islink(filepath):
                    hash = sha256_file(filepath)
                    assert (hash != None)
                    assert (filepath not in hashes)

                    hashes[filepath] = hash

        output = []
        for key in hashes.keys():
            entry = dict()
            entry["filepath"] = fs.path_remove_prefix(key, app.filepath + "/")
            entry["filesize"] = os.path.getsize(key)
            entry["hash"] = hashes[key]
            output.append(entry)

        return output

    def extract_data(self, app: Bundle, result_path: str) -> bool:
        assert(isinstance(app, Application))

        manifest = self._build_manifest(app)
        with open(os.path.join(result_path, "manifest.json"), "w") as outfile:
            json.dump(manifest, outfile, indent=4)

        return True
