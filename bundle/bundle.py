import os.path
import pathlib

# For comfortable directory walking
import os
import sys

from typing import List
import misc.plist as plist
import misc.filesystem as fs

from bundle.types import BundleType

import abc

class InvalidBundle(Exception):
    pass

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
        if not os.path.exists(normalized_path):
            raise ValueError("Invalid filepath specified.")

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
    def from_binary(filepath : str):
        """Finds the bundle that contains a specific binary.

        Throws a ValueError if the supplied binary is
            a) not a binary
            b) does not exist

        Returns
            On success: The bundle
            On failure: None
        """
        # Binary has to be valid file at the very least
        if not os.path.isfile(filepath):
            raise ValueError("Invalid executable specified")

        containing_dir = os.path.dirname(filepath)
        while containing_dir != "/":
            # Potential bundle found
            if Bundle.is_bundle(containing_dir):
                bun = Bundle.make(containing_dir)
                if not os.path.isfile(bun.executable_path()):
                    # File specified in Info.plist does not exist.
                    # This sometimes happens for applications with incorrectly
                    # configured frameworks. In these cases, as a workaround,
                    # we simply check whether the filepath of the current bundle
                    # is contained in the `bin_path`.
                    if os.path.commonpath([bun.filepath, filepath]) == bun.filepath:
                        return bun
                elif fs.is_same_file(bun.executable_path(), filepath):
                    return bun

            # Move up one level
            containing_dir = os.path.dirname(containing_dir)

        return None

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

    def executable(self):
        from binary.binary import Binary

        if hasattr(self, 'binary'):
            return self.binary

        linker_paths = self.linker_paths()
        self.binary = Binary(self.executable_path(),
                             executable_path=linker_paths[0],
                             loader_path=linker_paths[1])
        return self.binary


    @abc.abstractmethod
    def linker_paths(self):
        """Shall return tuple (@executable_path, @loader_path) that are used
        to resolve loaded libraries and frameworks."""
        raise NotImplementedError

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

    def version(self) -> str:
        info_dict = self.info_dictionary()

        version = None

        if "CFBundleShortVersionString" in info_dict:
            version = info_dict["CFBundleShortVersionString"]
        elif "CFBundleVersion" in info_dict():
            version = info_dict["CFBundleVersion"]

        return version

    def has_entitlements(self):
        return self.entitlements() != dict()

    def entitlements(self) -> dict:
        from binary.binary import Binary

        try:
            exe_path = self.executable_path()
            return Binary.get_entitlements(exe_path)
        except NotImplementedError:
            return dict()

    @abc.abstractmethod
    def info_dictionary_path(self) -> str:
        raise NotImplementedError()

    @staticmethod
    @abc.abstractmethod
    def supported_types(self) -> List[BundleType]:
        """Returns a list of supported bundle types for the current class"""

    def __str__(self):
        type = self.__class__.__name__
        version = "v" + self.version()
        identifier = self.info_dictionary()["CFBundleIdentifier"] \
            if "CFBundleIdentifier" in self.info_dictionary() \
            else "unknown.bundle"

        return " - ".join([type, identifier, version])