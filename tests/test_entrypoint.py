import unittest
import patchfinder.context as context
import patchfinder.entrypoint as entrypoint

class TestEntrypoint(unittest.TestCase):
    """Test Class for Entrypoint"""

    def test_entrypoint_init(self):
        vuln = context.create_vuln('CVE-2018-20406')
        entrypoints = vuln.entrypoints
        self.assertEqual(entrypoints[0].urls,
                         ['https://nvd.nist.org/vuln/details/CVE-2018-20406'])
        self.assertEqual(entrypoints[1].urls,
                         ['https://cve.mitre.org/cgi-bin/cvename.cgi?' \
                          'name=CVE-2018-20406'])

    def test_github_init(self):
        github = entrypoint.Github()
        link = 'https://github.com/python/cpython/commit/a4ae828ee416a6' \
                '6d8c7bf5ee71d653c2cc6a26dd'
        self.assertEqual(github.link_components, ['github.com', '/commit/'])
        github = entrypoint.Github('CVE-2018-20406')
        self.assertEqual(github.urls, ['https://github.com/search?q=CVE-2018-' \
                                      '20406&type=Commits'])
        self.assertEqual(github.link_components, ['github.com', '/commit/'])

    def test_github_match_link(self):
        github = entrypoint.Github()
        link = 'https://github.com/python/cpython/commit/a4ae828ee416a6' \
                '6d8c7bf5ee71d653c2cc6a26dd'
        self.assertTrue(github.match_link(link))
        link = 'https://github.com/python/cpython/pull/13797'
        self.assertFalse(github.match_link(link))

    def test_create_entrypoint(self):
        self.assertTrue(entrypoint.create_entrypoint('github'))
        self.assertTrue(entrypoint.create_entrypoint('cve.mitre.org', 'CVE-2016-4796'))
        self.assertFalse(entrypoint.create_entrypoint('opensuse', 'CVE-2016-4796'))

    def test_is_patch(self):
        patch_link = 'https://github.com/uclouvain/openjpeg/commit/162f6199c' \
                '0cd3ec1c6c6dc65e41b2faab92b2d91'
        self.assertTrue(entrypoint.is_patch(patch_link))


if __name__ == '__main__':
    unittest.main()
