import unittest
import patchfinder.spiders.default_spider as default_spider
from tests import fake_response_from_file

class TestSpider(unittest.TestCase):
    """Test Class for spiders"""

    def setUp(self):
        self.spider = default_spider.DefaultSpider()

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
                self.assertTrue(request.priority is 1)
        self.assertTrue(found_openwall)

    def test_patch_limit_with_parse(self):
        self.spider.patches = []
        self.spider.patch_limit = 2
        secl_response = fake_response_from_file('./mocks/1.html',
                                                'https://seclists.org' \
                                                '/oss-sec/2018/q3/179')
        nvd_response = fake_response_from_file('./mocks/2.html')
        nvd_requests_and_items = list(self.spider.parse(nvd_response))
        secl_requests_and_items = list(self.spider.parse(secl_response))
        self.assertTrue(len(secl_requests_and_items) is 1)
        self.assertTrue(len(self.spider.patches) is 2)


if __name__ == '__main__':
    unittest.main()
