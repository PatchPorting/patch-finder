import unittest
import unittest.mock as mock

from patchfinder.settings import Settings


class TestSettings(unittest.TestCase):
    """Test Class for the settings module"""

    def test_settings(self):
        def mock_dir(foo_arg):
            return [
                "FOO",
                "BAR",
                "BAZ",
                "BLARGH",
                "__builtins__",
                "__cached__",
                "__doc__",
                "__file__",
                "__loader__",
                "__name__",
            ]

        mock_module = mock.MagicMock()
        mock_module.__dir__ = mock_dir
        mock_module.FOO = 1
        mock_module.BAR = 2
        mock_module.BAZ = 3
        mock_module.BLARGH = 4
        settings = Settings(
            module=mock_module, values={"FOO": 5, "BLARGH": 6, "BARF": 7}
        )
        self.assertEqual(
            dict(settings), {"FOO": 5, "BAR": 2, "BAZ": 3, "BLARGH": 6}
        )


if __name__ == "__main__":
    unittest.main()
