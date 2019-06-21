import unittest
import patchfinder.context as context
import patchfinder.entrypoint as entrypoint

class TestEntrypoint(unittest.TestCase):
    """Test Class for Entrypoint"""

    def test_entrypoint_init(self):
        vuln = context.create_vuln('CVE-2018-20406')
        self.assertTrue('https://nvd.nist.gov/vuln/detail/CVE-2018-20406' \
                        in vuln.entrypoint_URLs)
        self.assertTrue('https://cve.mitre.org/cgi-bin/cvename.cgi?' \
                          'name=CVE-2018-20406' in vuln.entrypoint_URLs)

    def test_github_init(self):
        github = entrypoint.Github()
        link = 'https://github.com/python/cpython/commit/a4ae828ee416a6' \
                '6d8c7bf5ee71d653c2cc6a26dd'
        self.assertEqual(github.link_components, ['github\.com',
                                                  '/(commit|pull)/'])

    def test_github_match_link(self):
        github = entrypoint.Github()
        link = 'https://github.com/python/cpython/commit/a4ae828ee416a6' \
                '6d8c7bf5ee71d653c2cc6a26dd'
        self.assertTrue(github.match_link(link))
        link = 'https://github.com/python/cpython/pull/13797'
        self.assertTrue(github.match_link(link))

    def test_map_entrypoint_name(self):
        self.assertTrue(entrypoint.map_entrypoint_name('github.com'))
        self.assertFalse(entrypoint.map_entrypoint_name('opensuse'))

    def test_is_patch(self):
        link = 'https://github.com/uclouvain/openjpeg/commit/162f6199c' \
                '0cd3ec1c6c6dc65e41b2faab92b2d91'
        patch_link = entrypoint.is_patch(link)
        self.assertEqual(patch_link, 'https://github.com/uclouvain/openjpeg/' \
                         'commit/162f6199c0cd3ec1c6c6dc65e41b2faab92b2d91.pa' \
                         'tch')
        link = 'https://pagure.io/389-ds-base/c/4d9cc24da'
        patch_link = entrypoint.is_patch(link)
        self.assertEqual(patch_link, 'https://pagure.io/389-ds-base/c/4d9cc2' \
                         '4da.patch')

    def test_mitre_url_mapping(self):
        url = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4796'
        xpath = entrypoint.get_xpath(url)
        self.assertEqual(xpath, ['//*[@id="GeneratedTable"]/table/tr[7]/td//a'])

    def test_openwall_url_mapping(self):
        url = 'https://www.openwall.com/lists/oss-security/2016/05/13/2'
        xpath = entrypoint.get_xpath(url)
        self.assertEqual(xpath, ['//pre/a'])

    def test_fedoraproject_lists_url_mapping(self):
        url = 'https://lists.fedoraproject.org/archives/list/package-announ' \
                'ce@lists.fedoraproject.org/message/5FFMOZOF2EI6N2CR23EQ5EA' \
                'TWLQKBMHW/'
        xpath = entrypoint.get_xpath(url)
        self.assertEqual(xpath, ['//div[contains(@class, \'email-body\')]//a'])

    def test_debian_lists_url_mapping(self):
        url = 'https://lists.debian.org/debian-lts-announce/2019/05/msg0003' \
                '9.html'
        xpath = entrypoint.get_xpath(url)
        self.assertEqual(xpath, ['//pre/a'])

    def test_seclists_url_mapping(self):
        url = 'https://seclists.org/oss-sec/2018/q3/179'
        xpath = entrypoint.get_xpath(url)
        self.assertEqual(xpath, ['//pre/a'])



if __name__ == '__main__':
    unittest.main()
