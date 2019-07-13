import unittest
import unittest.mock as mock
from patchfinder.parsers import DebianParser

# TODO: Create more tests
# TODO: There should be some locally stored packages to test parsing logic on
# TODO: Individual tests for find_fixed_packages, extract_patches and retrieve_packages


class TestDebianParser(unittest.TestCase):
    """Test Class for DebianParser"""

    def setUp(self):
        self.parser = DebianParser()
        self.parser.cve_file = "./tests/mocks/mock_debian_cve_list"

    @mock.patch("patchfinder.parsers.debian_parser.utils.download_item")
    def test_fixed_packages(self, mock_download_method):
        vuln_id = "CVE-2019-12795"
        self.parser.set_context(vuln_id)
        self.parser.find_fixed_packages()
        mock_download_method.assert_called_with(
            self.parser.cve_list_url, self.parser.cve_file
        )
        self.assertTrue(
            {"package": "gvfs", "version": "1.38.1-5"}
            in self.parser.fixed_packages
        )
        self.assertEqual(len(self.parser.fixed_packages), 1)


if __name__ == "__main__":
    unittest.main()
