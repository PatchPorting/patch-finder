import unittest
import unittest.mock as mock

from patchfinder.utils import parse_web_page, download_item, member_in_tarfile


class TestUtils(unittest.TestCase):
    """Test Class for the utils modules"""

    @unittest.skip("Takes time")
    def test_parse_web_page(self):
        href = "https://bugzilla.redhat.com/show_bug.cgi?id=1317826"
        search_results = parse_web_page(href)
        print(search_results)

    @mock.patch("patchfinder.utils.urllib.request.urlopen")
    def test_parse_web_page_offline_for_normal_xpaths(self, mock_urlopen):
        """Strings from the normal xpaths should be scraped."""
        url = "https://security-tracker.debian.org/tracker/DSA-4444-1"
        try:
            f = open("./tests/mocks/debsec_dsa_4444_1.html")
            body = f.read()
        finally:
            f.close()
        expected_results = {
            "CVE-2018-12126",
            "CVE-2018-12127",
            "CVE-2018-12130",
            "CVE-2019-11091",
        }
        mock_html = mock.MagicMock()
        mock_html.read.return_value = body.encode()
        mock_urlopen.return_value = mock_html
        search_results = set(parse_web_page(url))
        self.assertEqual(expected_results, search_results)

    @mock.patch("patchfinder.utils.urllib.request")
    @mock.patch("patchfinder.utils.os")
    def test_download_item_file_exists(self, mock_os, mock_urllib_request):
        """Item should not be downloaded as it exists and overwrite is False."""
        file_name = "./tests/mocks/mock_file"
        file_url = "mock_url"
        mock_os.path.isfile.return_value = True
        download_item(file_url, file_name)
        mock_os.path.isfile.assert_called_with(file_name)
        mock_os.path.split.assert_not_called()
        mock_urllib_request.urlretrieve.assert_not_called()

    @mock.patch("patchfinder.utils.urllib.request")
    @mock.patch("patchfinder.utils.os")
    def test_download_item_file_not_exists(self, mock_os, mock_urllib_request):
        """Item should be downloaded as it does not exists."""
        file_name = "./tests/mocks/mock_file"
        file_url = "mock_url"
        mock_os.path.isfile.return_value = False
        mock_os.path.isdir.return_value = False
        mock_os.path.split.return_value = "."
        download_item(file_url, file_name)
        mock_os.path.isfile.assert_called_with(file_name)
        mock_os.path.split.assert_called_with(file_name)
        mock_urllib_request.urlretrieve.assert_called_with(file_url, file_name)

    def test_member_in_tarfile(self):
        """Members present should be found and absent should not be found."""
        tar_file = "./tests/mocks/openjpeg2_2.1.1-1.debian.tar.xz"
        self.assertTrue(member_in_tarfile(tar_file, "debian"))
        self.assertFalse(member_in_tarfile(tar_file, "deb"))
