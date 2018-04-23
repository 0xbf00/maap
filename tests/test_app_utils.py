from unittest import TestCase
from bundle.bundle import Bundle
import misc.app_utils as app_utils
from misc.filesystem import project_path


class TestAppUtils(TestCase):
    def test_get_sandbox_rules(self):
        # Load pre-existing result files
        with open(project_path("mas_tools/tests/data/calc_profile.sb"), "rb") as infile:
            calc_profile_sb = infile.read()
        with open(project_path("mas_tools/tests/data/calc_profile_patched.json"), "rb") as infile:
            calc_profile_patched_json = infile.read()

        bundle = Bundle.make("/Applications/Calculator.app")
        calc_profile = app_utils.get_sandbox_rules(bundle)
        self.assertEqual(calc_profile, calc_profile_sb)

        calc_profile = app_utils.get_sandbox_rules(bundle, result_format='json', patch=True)
        self.assertEqual(calc_profile, calc_profile_patched_json)

