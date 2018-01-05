import os.path
import pathlib

# For comfortable directory walking
import os

from typing import List
from enum import Enum, auto
import misc.plist as plist


class BundleType(Enum):
    APPLICATION    = auto()
    FRAMEWORK      = auto()
    APP_EXTENSION  = auto()
    PLUGIN         = auto()
    KEXT           = auto()
    GENERIC_BUNDLE = auto()
    XPC_EXTENSION  = auto()
    NONE           = auto()

    @staticmethod
    def type_for_bundle(bundlepath : str):
        """Uses the normalized path to determine the bundle's type"""
        BUNDLE_EXTENSIONS = {
            ".app": BundleType.APPLICATION,
            ".framework": BundleType.FRAMEWORK,
            ".bundle": BundleType.GENERIC_BUNDLE,
            # .appex is the extension for App Extensions, a form of bundles that are not part of the Bundle Programming
            # Guide
            # https://developer.apple.com/library/content/documentation/General/Conceptual/ExtensibilityPG/ExtensionCreation.html
            ".appex": BundleType.APP_EXTENSION,
            ".plugin": BundleType.PLUGIN,
            ".kext": BundleType.KEXT,
            ".xpc": BundleType.XPC_EXTENSION
        }

        (_, ext) = os.path.splitext(bundlepath)
        if ext in BUNDLE_EXTENSIONS:
            return BUNDLE_EXTENSIONS[ext]
        else:
            return BundleType.NONE


class Bundle:
    """The Bundle class models Bundles on macOS.

    It is heavily influenced by methods of the NSBundle class
    for the Objective-C programming language. It forms the
    base class for specialised classes such as Application and Framework.
    """

    def __init__(self, filepath):
        assert(Bundle.is_bundle(filepath))

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

        if not Bundle.is_bundle(filepath):
            return None

        normalized_path = Bundle.normalize_path(filepath)
        bundle_type = BundleType.type_for_bundle(normalized_path)

        try:
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
        except:
            # Upon closer inspection during initialization,
            # the bundle turns out not to be valid.
            # TODO Implement logging infrastructure with different levels and different output files.
            # print("{} does not appear to be valid bundle".format(filepath))
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
        dirname = Bundle.normalize_path(filepath)
        bundleType = BundleType.type_for_bundle(dirname)

        return bundleType != BundleType.NONE

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
            filter(lambda x: x.bundleType == BundleType.FRAMEWORK,
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

    def executable_path(self) -> str:
        raise NotImplementedError()

    def app_store_receipt_exists(self) -> bool:
        return os.path.isfile(self.app_store_receipt_path())

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

    def info_dictionary_path(self) -> str:
        raise NotImplementedError()
