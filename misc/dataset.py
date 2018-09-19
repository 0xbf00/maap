"""Functionality used for all scripts that want to access the App dataset"""

import os
import sqlite3
import datetime
from .filesystem import project_path


def _parse_timestamp(str):
    # Parses the time stamp used by Apple in their logging format
    # An example is "2018-03-21 16:54:32.543058+0100"
    return datetime.datetime.strptime(str, "%Y-%m-%dT%H:%M:%SZ")


def _version_info(bundle_id, version):
    VERSIONS_DB = project_path("mas_tools/scripts/app_versions/versions.db")
    if not os.path.exists(VERSIONS_DB):
        return
    
    conn = sqlite3.connect(VERSIONS_DB)

    c = conn.cursor()
    c.execute("SELECT version, release_date "
              "FROM versions JOIN apps on versions.app_id = apps.id "
              "WHERE bundle_id = ? and version = ?", (bundle_id, version, ))
    res = c.fetchone()
    if res is None:
        # Attempt a simpler match, by first checking whether the app itself is known,
        # and then checking whether the last version was released before we started
        # collecting.
        c.execute("SELECT version, release_date "
                  "FROM versions JOIN apps on versions.app_id = apps.id "
                  "WHERE bundle_id = ?", (bundle_id,))
        all_known_versions = c.fetchall()
        known_versions = sorted(all_known_versions,
                                key = lambda val: val[1],
                                reverse = True)

        # If we only have a single version, our version has got to be that version,
        # so return it.
        if len(known_versions) == 1:
            res = known_versions[0]

    if res:
        return {
            "version": res[0],
            "release_date": _parse_timestamp(res[1])
        }

    return None


class VersionSummary:
    """
    Class representing an application version. Provides method to access resources and to find
    out the release date of a version.
    """
    def __init__(self, filepath, bundle_id):
        self.filepath  = filepath
        self.bundle_id = bundle_id

        assert self.bundle_id in self.filepath
        assert os.path.exists(self.filepath)
        # For a valid app, we at least need the executable.
        assert self.resource_named("executable.bin") is not None

    def release_date(self):
        """
        The release date of the current version. This method is slow, as it consults with an external database.
        :return: Release date or None, if unknown
        """

        return _version_info(self.bundle_id, self.version_number())

    def version_number(self):
        """
        Get the version number of the current version
        This reads the version number from the directory of the app.
        """
        _, version = os.path.split(self.filepath)
        return version

    def resource_named(self, resource_name):
        """
        Get a path to a named resource. Returns None if there is no such
        resource
        """
        resource_path = os.path.join(self.filepath, resource_name)
        if os.path.exists(resource_path):
            return resource_path
        return None

    def new_resource(self, resource_name):
        """
        Returns the full path to a resource name, or returns None if the resource
        name is already used.
        """
        if self.resource_named(resource_name) is not None:
            return None

        return os.path.join(self.filepath, resource_name)


class AppEntry:
    """
    Class representing an application entry. Provides a way to iterate over all versions for an app
    """
    def __init__(self, filepath):
        self.filepath = filepath
        assert os.path.exists(self.filepath)

    def versions(self):
        """
        Generator of all app summaries available for individual versions
        """
        available_versions = [os.path.join(self.filepath, x) for x
                              in os.listdir(self.filepath) if not x.startswith(".")]
        app_bundle_id = self.bundle_id()

        for version in available_versions:
            try:
                yield VersionSummary(version, app_bundle_id)
            except AssertionError:
                print("{} is not a valid version.".format(version))
                continue

    def bundle_id(self):
        """
        The bundle id of the current application entry
        """
        _, bid = os.path.split(self.filepath)
        return bid


class Dataset:
    """
    Class representing an entire result dataset. Provides a way to iterate over all application entries
    """
    def __init__(self, filepath):
        """
        Initialises a new dataset object at a specified filepath.
        """
        self.filepath = filepath
        assert os.path.exists(self.filepath)

    def all_apps(self):
        """
        Generator of all app entries
        """
        available_apps = [os.path.join(self.filepath, x) for x
                          in os.listdir(self.filepath) if not x.startswith(".")]

        for app in available_apps:
            yield AppEntry(app)