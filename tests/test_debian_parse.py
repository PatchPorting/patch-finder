import unittest
import unittest.mock as mock
from patchfinder.settings import PatchfinderSettings
from patchfinder.parsers import DebianParser


class TestDebianParser(unittest.TestCase):
    """Test Class for DebianParser"""

    def setUp(self):
        self.parser = DebianParser()

    @mock.patch("patchfinder.parsers.debian_parser.utils.parse_web_page")
    @mock.patch("patchfinder.parsers.debian_parser.utils.download_item")
    def test_debian_parser(self, mock_download_item, mock_parse_page):
        vuln_id = "CVE-2016-4796"
        mock_parse_page.side_effect = [
            ["openjpeg", "(unfixed)", "openjpeg2", "2.1.1-1"],
            ["/pool/main/o/openjpeg2_2.1.1-1.debian.tar.xz"],
        ]
        self.parser.settings["DOWNLOAD_DIRECTORY"] = "./tests/mocks"
        patches = self.parser.parse(vuln_id)
        self.assertFalse(patches)


if __name__ == "__main__":
    unittest.main()
