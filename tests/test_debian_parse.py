import os
import tarfile
import shutil
import unittest
import unittest.mock as mock
import urllib.parse
import patchfinder.settings as settings
from patchfinder.parsers import DebianParser


class TestDebianParser(unittest.TestCase):
    """Test Class for DebianParser"""

    def setUp(self):
        self.parser = DebianParser()

    # Mocking settings temporarily, should do something better for this
    @mock.patch("patchfinder.parsers.debian_parser.settings")
    @mock.patch("patchfinder.parsers.debian_parser.utils.parse_web_page")
    @mock.patch("patchfinder.parsers.debian_parser.utils.download_item")
    def test_debian_parser(
        self, mock_download_item, mock_parse_page, mock_settings
    ):
        vuln_id = "CVE-2016-4796"
        mock_parse_page.side_effect = [
            ["openjpeg", "(unfixed)", "openjpeg2", "2.1.1-1"],
            ["/pool/main/o/openjpeg2_2.1.1-1.debian.tar.xz"],
        ]
        mock_settings.DOWNLOAD_DIRECTORY = "./tests/mocks"
        patches = self.parser.parse(vuln_id)
        self.assertFalse(patches)


if __name__ == "__main__":
    unittest.main()
