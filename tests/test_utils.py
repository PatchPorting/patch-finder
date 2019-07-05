import os
import re
import unittest
import unittest.mock as mock
import patchfinder.utils as utils
from patchfinder.parsers import DebianParser

class TestUtils(unittest.TestCase):
    """Test Class for the utils modules"""


    def test_parse_raw_file_with_debian_params(self):
        vuln_id = 'CVE-2016-4796'
        file_name = './tests/mocks/mock_debian_cve_list'
        debian_parser = DebianParser()
        debian_parser.set_context(vuln_id)
        matches = utils.parse_raw_file(file_name,
                                       debian_parser.file_start_block,
                                       debian_parser.file_end_block,
                                       debian_parser.pkg_ver_line)
        match = next(matches)
        self.assertTrue(match.group(1), 'openjpeg2')
        self.assertTrue(match.group(2), '2.1.1-1')
        self.assertEqual(len(match.groups()), 2)


    def test_parse_web_page(self):
        url = 'file://' + os.path.abspath('./tests/mocks/3.html')
        href = 'https://bugzilla.redhat.com/show_bug.cgi?id=1317826'
        regex = re.compile(r'/show_bug\.cgi\?id=\d{7}$')
        search_results = utils.parse_web_page(url, 'a', href=regex)
        self.assertEqual(search_results['href'], href)


    @mock.patch('patchfinder.utils.urllib.request')
    @mock.patch('patchfinder.utils.os')
    def test_download_item_file_exists(self, mock_os, mock_urllib_request):
        file_name = './tests/mocks/mock_file'
        file_url = 'mock_url'
        mock_os.path.isfile.return_value = True
        utils.download_item(file_url, file_name)
        mock_os.path.isfile.assert_called_with(file_name)
        mock_os.path.split.assert_not_called()
        mock_urllib_request.urlretrieve.assert_not_called()


    @mock.patch('patchfinder.utils.urllib.request')
    @mock.patch('patchfinder.utils.os')
    def test_download_item_file_not_exists(self, mock_os, mock_urllib_request):
        file_name = './tests/mocks/mock_file'
        file_url = 'mock_url'
        mock_os.path.isfile.return_value = False
        mock_os.path.isdir.return_value = False
        mock_os.path.split.return_value = '.'
        utils.download_item(file_url, file_name)
        mock_os.path.isfile.assert_called_with(file_name)
        mock_os.path.split.assert_called_with(file_name)
        mock_os.makedirs.assert_called_once()
        mock_urllib_request.urlretrieve.assert_called_with(file_url, file_name)


    def test_find_in_directory(self):
        files = list(utils.find_in_directory('./tests/mocks', 'mock'))
        self.assertIn('./tests/mocks/mock_debian_cve_list', files)
        self.assertIn('./tests/mocks/mock_file', files)


    def test_member_in_tarfile(self):
        tar_file = './tests/mocks/openjpeg2_2.1.1-1.debian.tar.xz'
        self.assertTrue(utils.member_in_tarfile(tar_file, 'debian'))
        self.assertFalse(utils.member_in_tarfile(tar_file, 'deb'))
