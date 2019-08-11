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
            xpaths=["//a/@href[contains(., 'openjpeg2_2.1.1-1.debian')]"],
        )
        self.assertFalse(patches)

    @mock.patch("patchfinder.parsers.debian_parser.utils.parse_web_page")
    @mock.patch("patchfinder.parsers.debian_parser.utils.download_item")
    def test_debian_parser_with_patches_in_package(
        self, mock_download_item, mock_parse_page
    ):
        """Patches should be found in the package.

        Tests:
            patchfinder.parsers.debian_parser.DebianParser.parse
        """
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
            xpaths=["//a/@href[contains(., 'libcaca_0.99.beta19-2.1.debian')]"],
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

    @mock.patch("patchfinder.parsers.debian_parser.utils.parse_web_page")
    @mock.patch("patchfinder.parsers.debian_parser.utils.download_item")
    def test_debian_parse_with_no_debian_tarball_found(
        self, mock_download_item, mock_parse_page
    ):
        """No debian tarball found on snapshot.d.o, so no patches found.

        Tests:
            patchfinder.parsers.debian_parser.DebianParser.parse
        """
        vuln_id = "CVE-2018-20406"
        mock_parse_page.side_effect = [
            ["python3.4", "(unfixed)", "python3.4", "3.4.2-1+deb8u2"],
            [],
        ]
        patches = self.parser.parse(vuln_id)
        mock_parse_page.assert_called_with(
            "https://snapshot.debian.org/package/python3.4/3.4.2-1+deb8u2/",
            xpaths=[
                "//a/@href[contains(., 'python3.4_3.4.2-1%2Bdeb8u2.debian')]"
            ],
        )

        # No packages were downloaded.
        mock_download_item.assert_not_called()
        self.assertFalse(patches)


if __name__ == "__main__":
    unittest.main()
