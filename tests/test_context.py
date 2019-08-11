import unittest

import patchfinder.context as context


class TestContext(unittest.TestCase):
    """Test Class for the context module"""

    def test_create_vuln_for_cve(self):
        """Vulnerability instantiation for a CVE"""
        vuln = context.create_vuln("CVE-2018-20406", {"upstream": ["python"]})
        self.assertTrue(vuln)

    def test_create_vuln_for_unknown_vuln(self):
        """Vulnerability instantiation for an unknown vulnerability"""
        vuln = context.create_vuln("foo bar")
        self.assertFalse(vuln)

    def test_create_vuln_for_inconsistent_cve(self):
        """Vulnerability instantiation for an inconsistent CVE notation"""
        vuln = context.create_vuln("cve 2019-4040")
        self.assertTrue(vuln)

    def test_create_vuln_for_dsa(self):
        """Vulnerability instantiation for a DSA"""
        vuln = context.create_vuln("DSA-4444-1")
        self.assertTrue(vuln)

    def test_create_vuln_for_glsa(self):
        """Vulnerability instantiation for a GLSA"""
        vuln = context.create_vuln("GLSA-200602-01")
        self.assertTrue(vuln)

    def test_create_vuln_for_rhsa(self):
        """Vulnerability instantiation for a RHSA"""
        vuln = context.create_vuln("RHSA-2019:0094")
        self.assertTrue(vuln)


if __name__ == "__main__":
    unittest.main()
