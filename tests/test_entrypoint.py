import unittest
import patchfinder.context as context

class TestEntrypoint(unittest.TestCase):
    """Test Class for Entrypoint"""

    def test_entrypoint_init(self):
        ctx = context.create_context('CVE-2018-20406')
        entrypoints = ctx.vuln.entrypoints
        self.assertEqual(entrypoints[0].urls,
                         ['https://nvd.nist.org/vuln/details/CVE-2018-20406'])
        self.assertEqual(entrypoints[1].urls,
                         ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20406'])


if __name__ == '__main__':
    unittest.main()
