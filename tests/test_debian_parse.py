import unittest
from patchfinder.debian import DebianParser

class TestDebianParser(unittest.TestCase):
    """Test Class for DebianParser"""

    def test_fixed_packages(self):
        debian_parser = DebianParser()
        debian_parser.vuln_id = 'CVE-2019-12795'
        pkgs = debian_parser.fixed_packages()
        self.assertTrue({'package':'gvfs', 'version': '1.38.1-5'} in pkgs)
        self.assertTrue(len(pkgs) is 1)
        debian_parser.vuln_id = 'CVE-2016-10739'
        pkgs = debian_parser.fixed_packages()
        self.assertTrue({'package': 'glibc', 'version': '2.28-6'} in pkgs)
        self.assertTrue(len(pkgs) is 1)
        debian_parser.vuln_id = 'CVE-2004-2779'
        pkgs = debian_parser.fixed_packages()
        self.assertTrue({'package': 'libid3tag', 'version': '0.15.1b-5'} in pkgs)
        self.assertTrue(len(pkgs) is 1)

if __name__ == '__main__':
    unittest.main()
