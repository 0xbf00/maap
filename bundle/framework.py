from bundle.bundle import Bundle
from bundle.types import BundleType

import os.path

FRMW_BASE_PATH = "Resources/"
INFO_DICT_PATH = os.path.join(FRMW_BASE_PATH, "Info.plist")
EXECUTABLE_DIR = os.path.join(FRMW_BASE_PATH, "..")

BUNDLE_EXECUTABLE_KEY = "CFBundleExecutable"
BUNDLE_IDENTIFIER_KEY = "CFBundleIdentifier"


class Framework(Bundle):
    """Documentation for this kind of Framework can be found here:
    https://developer.apple.com/library/content/documentation/MacOSX/Conceptual/BPFrameworks/Concepts/FrameworkAnatomy.html#//apple_ref/doc/uid/20002253-BAJEJJAB
    """
    def __init__(self, filepath):
        super(Framework, self).__init__(filepath)
        assert(BUNDLE_IDENTIFIER_KEY in self.info_dictionary())
        assert(BUNDLE_EXECUTABLE_KEY in self.info_dictionary())

    def info_dictionary_path(self):
        return self.absolute_path(INFO_DICT_PATH)

    def executable_path(self) -> str:
        info_dict = self.info_dictionary()
        executable_name = info_dict[BUNDLE_EXECUTABLE_KEY]

        return self.absolute_path(os.path.join(EXECUTABLE_DIR, executable_name))

    def linker_paths(self):
        # Frameworks inherit the executable path from the binary that is
        # loading them. At this point, we don't know which binary is loading
        # us (in general though, frameworks do not necessarily _need_ a single
        # containing application and therefore often don't need the @executable_path
        exe_path = None
        loader_path = self.absolute_path(EXECUTABLE_DIR)
        return (exe_path, loader_path)

    def app_store_receipt_path(self):
        raise NotImplementedError

    @staticmethod
    def supported_types(self):
        return [BundleType.FRAMEWORK]

