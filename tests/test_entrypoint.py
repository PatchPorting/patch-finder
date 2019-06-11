import unittest
import patchfinder.context as context
import patchfinder.entrypoint as entrypoint

class TestEntrypoint(unittest.TestCase):
    """Test Class for Entrypoint"""

    def test_entrypoint_init(self):
        vuln = context.create_vuln('CVE-2018-20406')
        entrypoints = vuln.entrypoints
        self.assertEqual(entrypoints[0].url,
                         'https://nvd.nist.gov/vuln/detail/CVE-2018-20406')
        self.assertEqual(entrypoints[1].url,
                         'https://cve.mitre.org/cgi-bin/cvename.cgi?' \
                          'name=CVE-2018-20406')

    def test_github_init(self):
        github = entrypoint.Github()
        link = 'https://github.com/python/cpython/commit/a4ae828ee416a6' \
                '6d8c7bf5ee71d653c2cc6a26dd'
        self.assertEqual(github.link_components, ['github\.com', '/commit/',
                                                  '[0-9a-f]{40}$'])
        github = entrypoint.Github('CVE-2018-20406')
        self.assertEqual(github.url, 'https://github.com/search?q=CVE-2018-' \
                                      '20406&type=Commits')
        self.assertEqual(github.link_components, [r'github\.com', r'/commit/', 
                                                  r'[0-9a-f]{40}$'])

    def test_nvd_init(self):
        nvd = entrypoint.NVD('CVE-2016-4796')
        self.assertEqual(nvd.name, 'nvd.nist.gov')
        self.assertEqual(nvd.xpaths, ['//table[@data-testid="vuln-hyperlinks-t' \
                         'able\"]/tbody//a'])

    def test_mitre_init(self):
        mitre = entrypoint.MITRE('CVE-2016-4796')
        self.assertEqual(mitre.name, 'cve.mitre.org')
        self.assertEqual(mitre.xpaths, ['//*[@id="GeneratedTable"]/table/tr[7]/t' \
                                       'd//a'])

    def test_github_match_link(self):
        github = entrypoint.Github()
        link = 'https://github.com/python/cpython/commit/a4ae828ee416a6' \
                '6d8c7bf5ee71d653c2cc6a26dd'
        self.assertTrue(github.match_link(link))
        link = 'https://github.com/python/cpython/pull/13797'
        self.assertFalse(github.match_link(link))

    def test_map_entrypoint_name(self):
        self.assertTrue(entrypoint.map_entrypoint_name('github.com', 'CVE-2016-4796'))
        self.assertFalse(entrypoint.map_entrypoint_name('opensuse', 'CVE-2016-4796'))

    def test_is_patch(self):
        patch_link = 'https://github.com/uclouvain/openjpeg/commit/162f6199c' \
                '0cd3ec1c6c6dc65e41b2faab92b2d91'
        self.assertTrue(entrypoint.is_patch(patch_link))

    def test_mitre_url_mapping(self):
        url = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4796'
        obj = entrypoint.get_entrypoint_from_url(url)
        self.assertEqual(obj.name, 'cve.mitre.org')

    def test_openwall_url_mapping(self):
        url = 'https://www.openwall.com/lists/oss-security/2016/05/13/2'
        obj = entrypoint.get_entrypoint_from_url(url)
        self.assertEqual(obj.name, 'openwall.com')

    def test_fedoraproject_lists_url_mapping(self):
        url = 'https://lists.fedoraproject.org/archives/list/package-announ' \
                'ce@lists.fedoraproject.org/message/5FFMOZOF2EI6N2CR23EQ5EA' \
                'TWLQKBMHW/'
        obj = entrypoint.get_entrypoint_from_url(url)
        self.assertEqual(obj.name, 'lists.fedoraproject.org')


if __name__ == '__main__':
    unittest.main()
