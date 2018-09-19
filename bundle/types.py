from enum import Enum, auto
from os.path import splitext

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

        (_, ext) = splitext(bundlepath)
        if ext in BUNDLE_EXTENSIONS:
            return BUNDLE_EXTENSIONS[ext]
        else:
            return BundleType.NONE

    def __str__(self):
        if self == BundleType.APPLICATION:
            return "application"
        elif self == BundleType.FRAMEWORK:
            return "framework"
        elif self == BundleType.APP_EXTENSION:
            return "app-extension"
        elif self == BundleType.PLUGIN:
            return "plugin"
        elif self == BundleType.KEXT:
            return "kext"
        elif self == BundleType.GENERIC_BUNDLE:
            return "generic-bundle"
        elif self == BundleType.XPC_EXTENSION:
            return "xpc-extension"
        elif self == BundleType.NONE:
            return "none-bundle"
        else:
            assert(False and "No string value known for BundleType")