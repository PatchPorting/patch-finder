import unittest
import patchfinder.context as context
import patchfinder.spiders.vuln_spider as vuln_spider

class TestVulnSpider(unittest.TestCase):
    """Test class for VulnSpider"""

    def setUp(self):
        #dummy vuln for testing
        vuln = context.UnparsableVulnerability('dummy_vuln',
                                               None,
                                               'https://example.com',
                                               None)
        self.spider = vuln_spider.VulnSpider(vuln)

    def test_callback_html(self):
        self.spider.vuln.parse_mode = 'html'
        callback = self.spider.callback()
        self.assertEqual(callback.__name__, 'parse_html')

    def test_callback_json(self):
        self.spider.vuln.parse_mode = 'json'
        callback = self.spider.callback()
        self.assertEqual(callback.__name__, 'parse_json')

    def test_callback_json(self):
        self.spider.vuln.parse_mode = 'plain'
        callback = self.spider.callback()
        self.assertEqual(callback.__name__, 'parse_plain')

    def test_start_requests(self):
        self.spider.vuln.parse_mode = 'html'
        request = next(self.spider.start_requests())
        self.assertEqual(request.url, self.spider.vuln.base_url)


if __name__ == '__main__':
    unittest.main()
