import os.path
import unittest
from patchfinder.debian import DebianParser
#TODO: Create more tests
#TODO: There should be some locally stored packages to test parsing logic on
#TODO: Individual tests for find_fixed_packages, extract_patches and retrieve_packages

class TestDebianParser(unittest.TestCase):
    """Test Class for DebianParser"""

    def test_fixed_packages(self):
        debian_parser = DebianParser()
        debian_parser.vuln_id = 'CVE-2019-12795'
        debian_parser.find_fixed_packages()
        self.assertTrue({'package':'gvfs', 'version': '1.38.1-5'} \
                        in debian_parser.fixed_packages)
        self.assertTrue(len(debian_parser.fixed_packages) is 1)
        debian_parser.vuln_id = 'CVE-2016-10739'
        debian_parser.find_fixed_packages()
        self.assertTrue({'package': 'glibc', 'version': '2.28-6'} \
                        in debian_parser.fixed_packages)
        self.assertTrue(len(debian_parser.fixed_packages) is 1)
        debian_parser.vuln_id = 'CVE-2004-2779'
        debian_parser.find_fixed_packages()
        self.assertTrue({'package': 'libid3tag', 'version': '0.15.1b-5'} \
                        in debian_parser.fixed_packages)
        self.assertTrue(len(debian_parser.fixed_packages) is 1)

    def test_debian_parse(self):
        debian_parser = DebianParser()
        pkg_name = 'openjpeg2_2.1.1-1.debian.tar.xz'
        patches = debian_parser.parse('CVE-2016-4796')
        self.assertTrue(os.path.isfile('./cache/' + pkg_name))
        self.assertFalse(patches)
        patches = debian_parser.parse('CVE-2004-2779')
        pkg_name = 'libid3tag_0.15.1b-5.diff.gz'
        self.assertTrue(os.path.isfile('./cache/' + pkg_name))
        self.assertFalse(patches)
        patches = debian_parser.parse('CVE-2017-8295')
        self.assertTrue(patches)

    def test_pkg_ver_in_line(self):
        debian_parser = DebianParser()
        line_1 = '\t- gvfs 1.38.1-5 (bug #930376)'
        line_2 = '\t- radare2 <unfixed> (bug #930344)'
        line_3 = '\t[experimental] - gitlab 11.10.5+dfsg-1'
        line_4 = '\t- enigmail 2:2.0.11+ds1-1 (bug #929363)'
        self.assertEqual(debian_parser.pkg_ver_in_line(line_1),
                         {'package': 'gvfs',
                          'version': '1.38.1-5'})
        self.assertFalse(debian_parser.pkg_ver_in_line(line_2))
        self.assertEqual(debian_parser.pkg_ver_in_line(line_3),
                         {'package': 'gitlab',
                          'version': '11.10.5+dfsg-1'})
        self.assertTrue(debian_parser.pkg_ver_in_line(line_4),
                        {'package': 'enigmail',
                         'version': '2.0.11+ds1-1'})

    def test_cve_file_name(self):
        debian_parser = DebianParser()
        self.assertEqual(debian_parser.cve_file, './cache/debian_cve_list')

if __name__ == '__main__':
    unittest.main()
