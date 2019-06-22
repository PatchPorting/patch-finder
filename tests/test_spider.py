import unittest
import patchfinder.spiders.default_spider as default_spider
import patchfinder.context as context
from tests import fake_response_from_file

class TestSpider(unittest.TestCase):
    """Test Class for spiders"""

    def setUp(self):
        self.spider = default_spider.DefaultSpider()

    def tearDown(self):
        self.spider = default_spider.DefaultSpider()

    def test_start_requests(self):
        vuln = context.create_vuln('CVE-2016-4796')
        self.spider = default_spider.DefaultSpider(vuln=vuln)
        requests = list(self.spider.start_requests())
        self.assertEqual(len(vuln.entrypoint_URLs), len(requests))

    def test_add_patch(self):
        patch_link = 'http://git.savannah.gnu.org/cgit/patch.git/commit/' \
                '?id=123eaff0d5d1aebe128295959435b9ca5909c26d'
        self.spider.add_patch(patch_link)
        self.assertTrue(patch_link in self.spider.patches)

    def test_extract_links(self):
        url = 'https://lists.fedoraproject.org/archives/list/package-a' \
                'nnounce@lists.fedoraproject.org/message/5FFMOZOF2EI6N' \
                '2CR23EQ5EATWLQKBMHW/'
        patch_link = 'https://github.com/uclouvain/openjpeg/commit/162' \
                'f6199c0cd3ec1c6c6dc65e41b2faab92b2d91.patch'
        absent_urls = ['https://docs.fedoraproject.org/yum/',
                       'https://fedoraproject.org/keys',
                       'https://lists.fedoraproject.org/']
        present_urls = ['https://bugzilla.redhat.com/show_bug.cgi?id=1317822',
                        'https://bugzilla.redhat.com/show_bug.cgi?id=1317826']
        response = fake_response_from_file('./mocks/3.html', url)
        links = self.spider.extract_links(response)
        self.assertTrue(all(url not in links['links']) for url in absent_urls)
        self.assertTrue(all(url in links['links']) for url in present_urls)
        self.assertEqual(len(links['patch_links']), 1)
        self.assertEqual(links['patch_links'], [patch_link])

    def test_parse_response(self):
        self.spider.important_domains.append('github.com')
        response = fake_response_from_file('./mocks/2.html')
        requests_and_items = list(self.spider.parse(response))

        patch_link = 'https://github.com/uclouvain/openjpeg/commit/162f619' \
                '9c0cd3ec1c6c6dc65e41b2faab92b2d91.patch'
        github_url = 'https://github.com/uclouvain/openjpeg/issues/774'
        openwall_url = 'http://www.openwall.com/lists/oss-security/2016/05/13/2'

        patch_item = requests_and_items.pop(0)
        self.assertEqual(patch_item['patch_link'], patch_link)
        found_openwall = 0

        for request in requests_and_items:
            if request.url == openwall_url:
                found_openwall = 1
            elif request.url == github_url:
                self.assertEqual(request.priority, 1)
        self.assertTrue(found_openwall)

    def test_patch_limit_with_parse(self):
        self.spider.patch_limit = 2
        secl_response = fake_response_from_file('./mocks/1.html',
                                                'https://seclists.org' \
                                                '/oss-sec/2018/q3/179')
        nvd_response = fake_response_from_file('./mocks/2.html')
        nvd_requests_and_items = list(self.spider.parse(nvd_response))
        secl_requests_and_items = list(self.spider.parse(secl_response))
        self.assertEqual(len(secl_requests_and_items), 1)
        self.assertEqual(len(self.spider.patches), 2)

    def test_no_debian_callback(self):
        self.spider.debian = False
        debian_url = 'https://security-tracker.debian.org/tracker/CVE-2018' \
                '-1000156'
        callback = self.spider.callback(debian_url)
        self.assertEqual(callback.__name__, 'parse')

    def test_debian_callback(self):
        self.spider.debian = True
        debian_url = 'https://security-tracker.debian.org/tracker/CVE-2018' \
                '-1000156'
        callback = self.spider.callback(debian_url)
        self.assertEqual(callback.__name__, 'parse_debian')


if __name__ == '__main__':
    unittest.main()
