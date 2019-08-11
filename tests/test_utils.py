import unittest
import unittest.mock as mock
from patchfinder.utils import parse_web_page, parse_dict, download_item, \
    member_in_tarfile


class TestUtils(unittest.TestCase):
    """Test Class for the utils modules"""

    @unittest.skip("Takes time")
    def test_parse_web_page(self):
        href = "https://bugzilla.redhat.com/show_bug.cgi?id=1317826"
        search_results = parse_web_page(href)
        print(search_results)

    @mock.patch("patchfinder.utils.urllib.request")
    @mock.patch("patchfinder.utils.os")
    def test_download_item_file_exists(self, mock_os, mock_urllib_request):
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
        tar_file = "./tests/mocks/openjpeg2_2.1.1-1.debian.tar.xz"
        self.assertTrue(member_in_tarfile(tar_file, "debian"))
        self.assertFalse(member_in_tarfile(tar_file, "deb"))
