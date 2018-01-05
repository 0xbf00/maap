from bundle.bundle import Bundle
from bundle.types import BundleType

from binary.binary import Binary

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
        assert(BUNDLE_IDENTIFIER_KEY in self.info_dictionary())
        assert(BUNDLE_EXECUTABLE_KEY in self.info_dictionary())

    def app_store_receipt_path(self):
        return self.absolute_path(RECEIPT_PATH)

    def info_dictionary_path(self):
        return self.absolute_path(INFO_DICT_PATH)

    def executable(self):
        if hasattr(self, 'binary'):
            return self.binary

        self.binary = Binary(self.executable_path(),
                             loader_path = self.absolute_path(EXECUTABLE_DIR),
                             executable_path = self.absolute_path(EXECUTABLE_DIR))
        return self.binary

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

    @staticmethod
    def supported_types(self):
        return [BundleType.APPLICATION]
