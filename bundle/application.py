from bundle.bundle import Bundle, InvalidBundle
from bundle.types import BundleType

import os.path

APP_BASE_PATH  = "Contents/"
RECEIPT_PATH   = os.path.join(APP_BASE_PATH, "_MASReceipt/receipt")
INFO_DICT_PATH = os.path.join(APP_BASE_PATH, "Info.plist")
EXECUTABLE_DIR = os.path.join(APP_BASE_PATH, "MacOS")

BUNDLE_EXECUTABLE_KEY = "CFBundleExecutable"
BUNDLE_IDENTIFIER_KEY = "CFBundleIdentifier"


class Application(Bundle):
    def __init__(self, filepath):
        super(Application, self).__init__(filepath)
        if BUNDLE_IDENTIFIER_KEY not in self.info_dictionary():
            raise InvalidBundle("CFBundleIdentifier missing.")
        if BUNDLE_EXECUTABLE_KEY not in self.info_dictionary():
            raise InvalidBundle("CFBundleExecutable missing.")

    def app_store_receipt_path(self):
        return self.absolute_path(RECEIPT_PATH)

    def info_dictionary_path(self):
        return self.absolute_path(INFO_DICT_PATH)

    def linker_paths(self):
        """Returns a tuple (executable_path, loader_path) which are used
        to expand @loader_path and @executable_path in load commands appropriately"""

        # For applications, loader and executable paths are identical.
        exe_path = self.absolute_path(EXECUTABLE_DIR)
        loader_path = exe_path

        return (exe_path, loader_path)

    def executable_path(self) -> str:
        info_dict = self.info_dictionary()
        executable_name = info_dict[BUNDLE_EXECUTABLE_KEY]

        return self.absolute_path(os.path.join(EXECUTABLE_DIR, executable_name))

    def is_mas_app(self):
        """Check if an app is from the App Store. To do this,
        we simply check whether there is a receipt file in the Application folder.
        Validating this file would be overkill, because we can assume that a) the
        apps have not been tampered with due to the test-system setup and b) all
        the information contained in the receipt is also available elsewhere
        (-> Info.plist) and c) validation is complicated, there are no readily
        available python bindings for Apple's APIs and OpenSSL is a huge
        dependency.

        For more info regarding the validation process, see
            - https://objective-see.com/blog/blog_0x10.html
            - https://www.objc.io/issues/17-security/receipt-validation/
        """
        return self.app_store_receipt_exists()

    def is_sandboxed(self):
        """Check if an app is sandboxed by the App Sandbox. This does not
        check whether the app itself voluntarily activates a sandbox and only
        returns true if it is forced into a sandbox."""
        if not self.has_entitlements():
            return False
        else:
            return "com.apple.security.app-sandbox" in self.entitlements() \
                   and self.entitlements()["com.apple.security.app-sandbox"]

    @staticmethod
    def supported_types(self):
        return [BundleType.APPLICATION]
