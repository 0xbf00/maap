from unittest import TestCase
from bundle.bundle import Bundle
import misc.app_utils as app_utils
from misc.filesystem import project_path


class TestAppUtils(TestCase):
    def test_get_sandbox_rules(self):
        bundle = Bundle.make("/Applications/Calculator.app")
        self.assertIsNotNone(app_utils.get_sandbox_rules(bundle))

