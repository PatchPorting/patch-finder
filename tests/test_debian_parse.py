import os.path
import unittest
from patchfinder.debian import DebianParser
#TODO: Create more tests

class TestDebianParser(unittest.TestCase):
    """Test Class for DebianParser"""

    def test_fixed_packages(self):
        debian_parser = DebianParser()
        debian_parser.vuln_id = 'CVE-2019-12795'
        debian_parser.find_fixed_packages()
        self.assertTrue({'package':'gvfs', 'version': '1.38.1-5'} in debian_parser.fixed_packages)
        self.assertTrue(len(debian_parser.fixed_packages) is 1)
        debian_parser.vuln_id = 'CVE-2016-10739'
        debian_parser.find_fixed_packages()
        self.assertTrue({'package': 'glibc', 'version': '2.28-6'} in debian_parser.fixed_packages)
        self.assertTrue(len(debian_parser.fixed_packages) is 1)
        debian_parser.vuln_id = 'CVE-2004-2779'
        debian_parser.find_fixed_packages()
        self.assertTrue({'package': 'libid3tag', 'version': '0.15.1b-5'} in debian_parser.fixed_packages)
        self.assertTrue(len(debian_parser.fixed_packages) is 1)

    def test_debian_parse(self):
        debian_parser = DebianParser()
        pkg_name = 'openjpeg2_2.1.1-1.debian.tar.xz'
        debian_parser.parse('CVE-2016-4796')
        self.assertTrue(os.path.isfile('./cache/' + pkg_name))
        debian_parser.parse('CVE-2004-2779')
        pkg_name = 'libid3tag_0.15.1b-5.diff.gz'
        self.assertTrue(os.path.isfile('./cache/' + pkg_name))

    def test_cve_file_name(self):
        debian_parser = DebianParser()
        self.assertEqual(debian_parser.cve_file, './cache/list')

if __name__ == '__main__':
    unittest.main()
