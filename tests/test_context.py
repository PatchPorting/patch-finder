import unittest
import patchfinder.context as context
import patchfinder.settings as settings


class TestContext(unittest.TestCase):
    """Test Class for the context module"""

    def test_cve_init(self):
        vuln_id = "CVE-2019-1010"
        vuln = context.CVE(vuln_id)
        self.assertEqual(vuln.vuln_id, vuln_id)
        vuln = context.CVE(
            vuln_id, {"upstream": ["graphicsmagick", "Imagemagick"]}
        )
        self.assertEqual(
            vuln.packages, {"upstream": ["graphicsmagick", "Imagemagick"]}
        )

    def test_create_vuln(self):
        vuln = context.create_vuln("CVE-2018-20406", {"upstream": ["python"]})
        self.assertEqual(vuln.vuln_id, "CVE-2018-20406")
        self.assertEqual(vuln.packages, {"upstream": ["python"]})
        vuln = context.create_vuln("TALOS-2018-20406", {"upstream": ["python"]})
        self.assertEqual(vuln, None)

    def test_dsa_init(self):
        vuln_id = "DSA-4431-1"
        vuln = context.DSA(vuln_id)
        self.assertEqual(vuln.vuln_id, vuln_id)


if __name__ == "__main__":
    unittest.main()
