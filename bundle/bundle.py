import os.path
import pathlib

# For comfortable directory walking
import os
import sys

from typing import List
import misc.plist as plist

from bundle.types import BundleType

import abc

class Bundle(abc.ABC):
    """The Bundle class models Bundles on macOS.

    It is heavily influenced by methods of the NSBundle class
    for the Objective-C programming language. It forms the
    base class for specialised classes such as Application and Framework.
    """
    @abc.abstractmethod
    def __init__(self, filepath):
        normalized_path  = Bundle.normalize_path(filepath)
        self.filepath   = normalized_path
        self.bundle_type = BundleType.type_for_bundle(normalized_path)

        # A proper Bundle has this key in its Info.plist
        assert("CFBundlePackageType" in self.info_dictionary())

    @staticmethod
    def make(filepath : str):
        # Imports have to be done here, because otherwise
        # circular dependencies stop us from doing anything
        from bundle.application import Application
        from bundle.framework import Framework
        from bundle.generic import GenericBundle

        normalized_path = Bundle.normalize_path(filepath)
        bundle_type = BundleType.type_for_bundle(normalized_path)

        if bundle_type == BundleType.APPLICATION:
            return Application(filepath)
        elif bundle_type == BundleType.FRAMEWORK:
            return Framework(filepath)
        elif bundle_type == BundleType.GENERIC_BUNDLE:
            return GenericBundle(filepath)
        elif bundle_type == BundleType.APP_EXTENSION:
            return GenericBundle(filepath)
        elif bundle_type == BundleType.PLUGIN:
            return GenericBundle(filepath)
        elif bundle_type == BundleType.KEXT:
            return GenericBundle(filepath)
        elif bundle_type == BundleType.XPC_EXTENSION:
            return GenericBundle(filepath)
        else:
            raise NotImplementedError

    @staticmethod
    def normalize_path(filepath : str) -> str:
        """Attempt to normalize paths, s.t. /Applications/Xcode.app and
        /Applications/Xcode.app/, as well as /Applications/Xcode.app/Test
        are all mapped to a canonical version -- no terminating slashes
        and the path of a directory"""
        if filepath.endswith("/"):
            filepath = filepath[:-1]

        if not os.path.isdir(filepath):
            filepath = os.path.dirname(filepath)

        return filepath

    @staticmethod
    def is_bundle(filepath : str) -> bool:
        normalized_path = Bundle.normalize_path(filepath)
        bundle_type = BundleType.type_for_bundle(normalized_path)

        try:
            bundle = Bundle.make(filepath)
            return True
        except:
            # if bundle_type != BundleType.NONE:
                # print("Bundle \"{}\" could not be read, despite seemingly being a bundle.".format(normalized_path))
            return False

    def bundle_identifier(self) -> str:
        """Returns the bundle identifier of the current bundle.

        This assumes a bundle identifier exists!"""
        assert(self.has_bundle_identifier())
        return self.info_dictionary()["CFBundleIdentifier"]

    def has_bundle_identifier(self) -> bool:
        return "CFBundleIdentifier" in self.info_dictionary()

    def sub_bundles(self) -> List['Bundle']:
        """Search all subdirectories for other Bundles
        and return everything we find."""
        subBundles = []

        for root, dirs, _ in os.walk(self.filepath):
            if root != self.filepath and Bundle.is_bundle(root):
                bundle = Bundle.make(root)
                if bundle:
                    subBundles.append(bundle)
                dirs[:] = []

        return subBundles

    def sub_frameworks(self) -> List['Bundle']:
        """Return only Frameworks (as opposed to all bundles) that are part of another bundle"""
        all_bundles = self.sub_bundles()
        return list(
            filter(lambda x: x.bundle_type == BundleType.FRAMEWORK,
                   all_bundles)
            )

    def absolute_path(self, relative_path : str) -> str:
        assert(not relative_path.startswith("/"))

        return str(pathlib.Path(os.path.join(self.filepath, relative_path)).resolve())

    def path_for_resource(self, relative_path):
        """Convert relative path to absolute path.
        Given a relative path, such as Contents/Info.plist,
        yields the absolute path, taking into consideration the
        base path of the application. Returns None in case
        the desired resource could not be found."""
        abs_path = self.absolute_path(relative_path)
        return abs_path if os.path.exists(abs_path) else None

    @abc.abstractmethod
    def executable_path(self) -> str:
        raise NotImplementedError()

    def app_store_receipt_exists(self) -> bool:
        return os.path.isfile(self.app_store_receipt_path())

    @abc.abstractmethod
    def app_store_receipt_path(self) -> str:
        raise NotImplementedError()

    def info_dictionary(self) -> dict:
        if hasattr(self, "info_dict"):
            return self.info_dict

        info_dictionary_at = self.info_dictionary_path()
        self.info_dict = plist.parse_resilient(info_dictionary_at)
        if not self.info_dict:
            raise ValueError("Invalid Info.plist file")

        return self.info_dict

    @abc.abstractmethod
    def info_dictionary_path(self) -> str:
        raise NotImplementedError()

    @staticmethod
    @abc.abstractmethod
    def supported_types(self) -> List[BundleType]:
        """Returns a list of supported bundle types for the current class"""

    def __str__(self):
        type = self.__class__.__name__
        version = "v" + self.info_dictionary()["CFBundleShortVersionString"] \
            if "CFBundleShortVersionString" in self.info_dictionary() \
            else "vUNKOWN"
        identifier = self.info_dictionary()["CFBundleIdentifier"] \
            if "CFBundleIdentifier" in self.info_dictionary() \
            else "unknown.bundle"

        return " - ".join([type, identifier, version])