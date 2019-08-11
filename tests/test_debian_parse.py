import unittest
import unittest.mock as mock
from patchfinder.parsers import DebianParser


class TestDebianParser(unittest.TestCase):
    """Test Class for DebianParser"""

    def setUp(self):
        self.parser = DebianParser()
        self.parser.settings["DOWNLOAD_DIRECTORY"] = "./tests/mocks"

    @mock.patch("patchfinder.parsers.debian_parser.utils.parse_web_page")
    @mock.patch("patchfinder.parsers.debian_parser.utils.download_item")
    def test_debian_parser_with_no_patches_in_package(
        self, mock_download_item, mock_parse_page
    ):
        """No patches should be found in this package.

        Tests:
            patchfinder.parsers.debian_parser.DebianParser.parse
        """
        vuln_id = "CVE-2016-4796"
        mock_parse_page.side_effect = [
            ["openjpeg", "(unfixed)", "openjpeg2", "2.1.1-1"],
            ["/pool/main/o/openjpeg2_2.1.1-1.debian.tar.xz"],
        ]
        patches = self.parser.parse(vuln_id)
        mock_parse_page.assert_called_with(
            "https://snapshot.debian.org/package/openjpeg2/2.1.1-1/",
            xpaths=["//a/@href[contains(., 'openjpeg2_2.1.1-1.debian')]"]
        )
        self.assertFalse(patches)

    @mock.patch("patchfinder.parsers.debian_parser.utils.parse_web_page")
    @mock.patch("patchfinder.parsers.debian_parser.utils.download_item")
    def test_debian_parser_with_patches_in_package(
        self, mock_download_item, mock_parse_page
    ):
        vuln_id = "CVE-2018-20544"
        mock_parse_page.side_effect = [
            ["libcaca", "0.99.beta19-2.1"],
            [
                "/pool/main/libc/libcaca/libcaca_0.99.beta19-2.1.debian.tar.xz",
                "/archive/debian-debug/20190409T031248Z/pool/main/libc/libcaca"
                "/libcaca_0.99.beta19-2.1.debian.tar.xz",
            ],
        ]
        patches = self.parser.parse(vuln_id)
        mock_parse_page.assert_called_with(
            "https://snapshot.debian.org/package/libcaca/0.99.beta19-2.1/",
            xpaths=["//a/@href[contains(., 'libcaca_0.99.beta19-2.1.debian')]"]
        )
        self.assertIn(
            {
                "patch_link": "debian/patches/CVE-2018-20544.patch",
                "reaching_path": (
                    "https://snapshot.debian.org/archive/"
                    "debian-debug/20190409T031248Z/pool/main/libc/libcaca/"
                    "libcaca_0.99.beta19-2.1.debian.tar.xz"
                ),
            },
            patches,
        )


if __name__ == "__main__":
    unittest.main()
