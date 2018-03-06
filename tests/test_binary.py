"""Tests for the binary/binary.py file implementing the Binary() class."""

import unittest

import binary.binary as bin


class TestBinary(unittest.TestCase):
    def test_creation(self):
        # Successful loading
        loaded_bin = bin.Binary("/Applications/Calculator.app/Contents/MacOS/Calculator")
        self.assertIsInstance(loaded_bin, bin.Binary)

        # Non-existent file loading
        with self.assertRaises(ValueError):
            loaded_bin = bin.Binary("/Applications/Calculator.app/Contents/MacO/Calculator")

    def test_application_libraries(self):
        # Application libraries are those linked libraries
        # that are part of the application bundle.
        # Other libraries -- most notable system frameworks and
        # libraries -- should not be present here.

        # Calculator does not have frameworks / libraries that are part of it's application bundle
        calc_bin = bin.Binary("/Applications/Calculator.app/Contents/MacOS/Calculator")
        self.assertEqual(calc_bin.application_libraries(), [])

        # iTunes does have a bunch of application specific libraries (though there are not
        # specified relatively, but using the complete path!)
        # Again, extracted using otool -L!
        itunes_application_libraries = [
            "/Applications/iTunes.app/Contents/Frameworks/iPodUpdater.framework/Versions/A/iPodUpdater",
            "/Applications/iTunes.app/Contents/Frameworks/libgnsdk_dsp.3.06.1.dylib",
            "/Applications/iTunes.app/Contents/Frameworks/libgnsdk_manager.3.06.1.dylib",
            "/Applications/iTunes.app/Contents/Frameworks/libgnsdk_musicid.3.06.1.dylib",
            "/Applications/iTunes.app/Contents/Frameworks/libgnsdk_submit.3.06.1.dylib",
        ]

        itunes_bin = bin.Binary("/Applications/iTunes.app/Contents/MacOS/iTunes")
        itunes_app_libraries = itunes_bin.application_libraries()
        self.assertTrue(len(itunes_app_libraries) == len(itunes_application_libraries))
        for app_library in itunes_app_libraries:
            self.assertIn(app_library, itunes_application_libraries)

    def test_linked_libraries(self):
        # Testing Calculator.app. This application does not make use of @rpath, @executable_path, ...
        # Generated using `otool -L /Applications/Calculator.app/Contents/MacOS/Calculator`
        calculator_expected_libraries = [
            "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa",
            "/System/Library/PrivateFrameworks/SpeechDictionary.framework/Versions/A/SpeechDictionary",
            "/System/Library/PrivateFrameworks/SpeechObjects.framework/Versions/A/SpeechObjects",
            "/System/Library/PrivateFrameworks/Calculate.framework/Versions/A/Calculate",
            "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices",
            "/System/Library/Frameworks/QuartzCore.framework/Versions/A/QuartzCore",
            "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation",
            "/usr/lib/libobjc.A.dylib",
            "/usr/lib/libSystem.B.dylib",
            "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit",
            "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
            "/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics"
        ]

        loaded_binary = bin.Binary("/Applications/Calculator.app/Contents/MacOS/Calculator")
        linked_libs = loaded_binary.linked_libraries()
        self.assertTrue(len(linked_libs) == len(calculator_expected_libraries))
        for linked_lib in linked_libs:
            self.assertIn(linked_lib, calculator_expected_libraries, "Found library not present in static information")

    def test_get_entitlements(self):
        # Assuming the entitlements in system apps do not change much.
        computed_entitlements = bin.Binary.get_entitlements("/Applications/Calculator.app/Contents/MacOS/Calculator")
        desired_entitlements = {
            "com.apple.security.app-sandbox": True,
            "com.apple.security.files.user-selected.read-write": True,
            "com.apple.security.network.client": True,
            "com.apple.security.print": True
        }

        self.assertEqual(desired_entitlements, computed_entitlements)

        # So far, /bin/ls contains no entitlements
        self.assertEqual(bin.Binary.get_entitlements("/bin/ls"), dict())