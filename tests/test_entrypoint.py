import unittest
import patchfinder.context as context
import patchfinder.entrypoint as entrypoint

class TestEntrypoint(unittest.TestCase):
    """Test Class for Entrypoint"""

    def test_entrypoint_init(self):
        ctx = context.create_context('CVE-2018-20406')
        entrypoints = ctx.vuln.entrypoints
        self.assertEqual(entrypoints[0].urls,
                         ['https://nvd.nist.org/vuln/details/CVE-2018-20406'])
        self.assertEqual(entrypoints[1].urls,
                         ['https://cve.mitre.org/cgi-bin/cvename.cgi?' \
                          'name=CVE-2018-20406'])

    def test_github(self):
        github = entrypoint.Github()
        link = 'https://github.com/python/cpython/commit/a4ae828ee416a6' \
                '6d8c7bf5ee71d653c2cc6a26dd'
        self.assertEqual(github.link_components, ['github.com', '/commit/'])
        github = entrypoint.Github('CVE-2018-20406')
        self.assertEqual(github.urls, ['https://github.com/search?q=CVE-2018-' \
                                      '20406&type=Commits'])
        self.assertEqual(github.link_components, ['github.com', '/commit/'])


if __name__ == '__main__':
    unittest.main()
