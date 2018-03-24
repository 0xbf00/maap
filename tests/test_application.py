import unittest

import os.path
from bundle.bundle import Bundle
from bundle.types import BundleType

# List of commonly installed apps.
MAS_APPS = ["Pages.app", "Keynote.app", "Numbers.app", "WhatsApp.app", "Xcode.app", "The Unarchiver.app"]
MAS_APP = None
for app in MAS_APPS:
    path = os.path.join("/Applications/", app)
    if os.path.exists(path):
        MAS_APP = path
        break
else:
    assert(False and "Please install one of these free apps from the Mac App Store: {}".format(MAS_APPS))


class TestApplication(unittest.TestCase):
    """Tests for the Application class"""
    def setUp(self):
        if MAS_APP:
            self.mas_app = Bundle.make(MAS_APP)
        else:
            self.mas_app = None
        # The Calculator.app app has been part of macOS for as long as I can think.
        # There is no risk this app is going anywhere.
        self.system_app = Bundle.make("/Applications/Calculator.app")

    def test_bundle_type(self):
        self.assertEqual(self.mas_app.bundle_type, BundleType.APPLICATION)
        self.assertEqual(self.system_app.bundle_type, BundleType.APPLICATION)

    def test_mas_app(self):
        self.assertIsNotNone(self.mas_app)
        self.assertTrue(self.mas_app.is_mas_app())

        self.assertFalse(self.system_app.is_mas_app())

    def test_paths(self):
        # Since we don't know which MAS app is chosen, only the system app is tested here.
        self.assertEqual(self.system_app.executable_path(), "/Applications/Calculator.app/Contents/MacOS/Calculator")
        self.assertEqual(self.system_app.info_dictionary_path(), "/Applications/Calculator.app/Contents/Info.plist")

    def test_executable(self):
        bin = self.system_app.executable()
        self.assertIsNotNone(bin)

    def test_loaded_libraries(self):
        app = self.system_app
        bin = app.executable()

        self.assertCountEqual(bin.application_libraries(), [])
        self.assertTrue(len(bin.linked_libraries()) == 12)
