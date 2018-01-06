import unittest
import os

from bundle.bundle import Bundle
from bundle.types import BundleType


class TestBundle(unittest.TestCase):
    """Tests for the `Bundle` class"""
    def setUp(self):
        # The Calculator.app app has been part of macOS for as long as I can think.
        # There is no risk this app is going anywhere.
        self.app = Bundle.make("/Applications/Calculator.app")

    def test_info_fns(self):
        self.assertTrue(self.app.has_bundle_identifier())
        self.assertEqual(self.app.bundle_identifier(), "com.apple.calculator")

    def test_is_bundle(self):
        self.assertTrue(Bundle.is_bundle("/Applications/Calculator.app"))
        self.assertTrue(Bundle.is_bundle("/System/Library/Frameworks/WebKit.framework"))

    def test_make_bundle(self):
        # Check common applications
        self.assertEqual(Bundle.make("/Applications/Calculator.app").bundle_type,
                         BundleType.APPLICATION)
        self.assertEqual(Bundle.make("/Applications/Safari.app").bundle_type,
                         BundleType.APPLICATION)

        # Check framework
        self.assertEqual(Bundle.make("/System/Library/Frameworks/Accelerate.framework").bundle_type,
                         BundleType.FRAMEWORK)

        # KEXTs, even though actual proper support is not implemented yet.
        self.assertEqual(Bundle.make("/System/Library/Extensions/AppleHWSensor.kext").bundle_type,
                         BundleType.KEXT)

        # Check failure cases
        with self.assertRaises(ValueError):
            Bundle.make("/System/Library/Frameworks/vecLib.framework")
        with self.assertRaises(AssertionError):
            Bundle.make("/System/Library/Frameworks/Kernel.framework")

    def test_path_for_resource(self):
        self.assertEqual(self.app.info_dictionary_path(),
                         self.app.path_for_resource("Contents/Info.plist"))

    def test_normalize_path(self):
        self.assertEqual(Bundle.normalize_path("/Applications/Xcode.app/"), "/Applications/Xcode.app")
        self.assertEqual(Bundle.normalize_path("/Applications/Xcode.app"), "/Applications/Xcode.app")
        self.assertEqual(Bundle.normalize_path("/Applications/Xcode.app/Test"), "/Applications/Xcode.app")

    def test_sub_frameworks(self):
        app = Bundle.make("/Applications/iTunes.app")
        sub_frameworks = app.sub_frameworks()

        self.assertEqual(1, len(sub_frameworks))
        self.assertEqual("/Applications/iTunes.app/Contents/Frameworks/iPodUpdater.framework",
                         sub_frameworks[0].filepath)

    def test_sub_subles(self):
        app = Bundle.make("/Applications/iTunes.app")
        sub_bundle_paths = [x.filepath for x in app.sub_bundles()]

        required_paths = [
            "/Applications/iTunes.app/Contents/XPCServices/VisualizerService.xpc",
            "/Applications/iTunes.app/Contents/PlugIns/iTunesStorageExtension.appex",
            "/Applications/iTunes.app/Contents/MacOS/iTunesHelper.app"
        ]

        for path in required_paths:
            self.assertIn(path, sub_bundle_paths)
