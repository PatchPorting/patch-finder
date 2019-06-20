import unittest
import patchfinder.spiders.default_spider as default_spider
from tests import fake_response_from_file

class TestSpider(unittest.TestCase):
    """Test Class for spiders"""

    def setUp(self):
        self.spider = default_spider.DefaultSpider()

    def test_extract_links(self):
        response = fake_response_from_file('./mocks/nvd_cve_2016_4796.html',
                                           'https://nvd.nist.gov/vuln/deta' \
                                           'il/CVE-2016-4796')
        links = self.spider.extract_links(response)
        patch_link = 'https://github.com/uclouvain/openjpeg/commit/162f619' \
                '9c0cd3ec1c6c6dc65e41b2faab92b2d91.patch'
        self.assertEqual(links['patch_links'][0], patch_link)
        self.assertTrue(len(links['patch_links']) is 1)


if __name__ == '__main__':
    unittest.main()
