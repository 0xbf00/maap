"""Test for routines defined in binary/common.py"""

import unittest
import binary.common

import lief

class TestBinCommon(unittest.TestCase):
    def test_resolve_library_path(self):
        calculator_data = {
            "path": "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa",
            "loader_path": "/Applications/Calculator.app/Contents/MacOS",
            "executable_path": "/Applications/Calculator.app/Contents/MacOS",
            "rpaths": []
        }

        # For the calculator data, the library path should be returned unchanged
        calculator_result = binary.common.resolve_library_path(**calculator_data)
        self.assertEqual(calculator_result, calculator_data["path"])


        # Taken from Fantastical 2.app
        fantastical_data = {
            # One of the many dependencies
            "path": "@rpath/HockeySDK.framework/Versions/A/HockeySDK",
            "loader_path": "/Applications/Fantastical 2.app/Contents/MacOS",
            "executable_path": "/Applications/Fantastical 2.app/Contents/MacOS",
            "rpaths": ['/Applications/Fantastical 2.app/Contents/MacOS/../Frameworks']
        }

        fantastical_result = binary.common.resolve_library_path(**fantastical_data)

        fantastical_desired_result = "/Applications/Fantastical 2.app/Contents/Frameworks/HockeySDK.framework/Versions/A/HockeySDK"
        self.assertEqual(fantastical_result, fantastical_desired_result)

        # Taken from Bear.app
        bear_data = {
            "path": "@executable_path/../Frameworks/MASShortcut.framework/Versions/A/MASShortcut",
            "loader_path": "/Applications/Bear.app/Contents/MacOS",
            "executable_path": "/Applications/Bear.app/Contents/MacOS",
            "rpaths": ['/Applications/Bear.app/Contents/MacOS/../Frameworks']
        }

        bear_result = binary.common.resolve_library_path(**bear_data)

        # @executable_path should be replaced, relative path components should be eliminated
        bear_desired_result = "/Applications/Bear.app/Contents/Frameworks/MASShortcut.framework/Versions/A/MASShortcut"
        self.assertEqual(bear_result, bear_desired_result)

        # Test error handling
        fantastical_data_err = {
            # One of the many dependencies
            "path": "@rpath/HockeySDK.framework/Versions/A/HockeySDK",
            "loader_path": "/Applications/Fantastical 2.app/Contents/MacOS",
            "executable_path": "/Applications/Fantastical 2.app/Contents/MacOS",
            "rpaths": []
        }

        with self.assertRaises(ValueError):
            binary.common.resolve_library_path(**fantastical_data_err)

    def test_extract_rpaths(self):
        import os.path

        self.assertTrue(os.path.exists("/Applications/WhatsApp.app/Contents/MacOS/WhatsApp"), "WhatsApp is not installed.")

        bin = lief.parse("/Applications/WhatsApp.app/Contents/MacOS/WhatsApp")

        actual_whatsapp_rpaths = ["/Applications/WhatsApp.app/Contents/MacOS/../Frameworks"]
        computed_whatsapp_rpaths = binary.common.extract_rpaths(bin,
                                                                "/Applications/WhatsApp.app/Contents/MacOS",
                                                                "/Applications/WhatsApp.app/Contents/MacOS")
        self.assertEqual(actual_whatsapp_rpaths, computed_whatsapp_rpaths)

        # iTunes (and all other built-in binaries) do(es) not have @rpath commands
        itunes_bin = lief.parse("/Applications/iTunes.app/Contents/MacOS/iTunes")
        self.assertEqual(binary.common.extract_rpaths(itunes_bin,
                                                      "/Applications/iTunes.app/Contents/MacOS",
                                                      "/Applications/iTunes.app/Contents/MacOS"),
                      [])

    def test_bundle_from_binary(self):
        # For single-file utility, this function should return None, because the file is not
        # part of any bundle
        self.assertIsNone(binary.common.bundle_from_binary("/bin/ls"))
        self.assertIsNone(binary.common.bundle_from_binary("/bin/ln"))

        # For binaries that are part of a bundle but not the main executable in such a bundle,
        # the function is also supposed to return None

        # Note: iTunes is used here, because it comes pre-installed on macOS
        # and it has the most complicated dependencies of any installed app, thus
        # it can be used for many different purposes
        self.assertIsNone(binary.common.bundle_from_binary("/Applications/iTunes.app/Contents/MacOS/iTunesASUHelper"))

        # For non-existent binaries, the function should throw a ValueError
        with self.assertRaises(ValueError):
            # This binary surely does not exist
            binary.common.bundle_from_binary("/bin/useful_test03837246")

        # If the main executable is supplied, the corresponding bundle should be found
        self.assertEqual(
            binary.common.bundle_from_binary(
                "/Applications/iTunes.app/Contents/MacOS/iTunes"
            ).filepath,
            "/Applications/iTunes.app")

        # This should also work for other types of bundles
        self.assertEqual(
            binary.common.bundle_from_binary(
                "/Applications/iTunes.app/Contents/Frameworks/iPodUpdater.framework/Versions/A/iPodUpdater"
            ).filepath,
            "/Applications/iTunes.app/Contents/Frameworks/iPodUpdater.framework"
        )
        self.assertEqual(
            binary.common.bundle_from_binary(
                "/Applications/iTunes.app/Contents/PlugIns/iTunesStorageExtension.appex/Contents/MacOS/iTunesStorageExtension"
            ).filepath,
            "/Applications/iTunes.app/Contents/PlugIns/iTunesStorageExtension.appex"
        )