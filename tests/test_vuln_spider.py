import unittest
import unittest.mock as mock
import patchfinder.context as context
import patchfinder.spiders.vuln_spider as vuln_spider
import patchfinder.settings as settings
from tests import fake_response_from_file

class TestVulnSpider(unittest.TestCase):
    """Test class for VulnSpider"""

    def setUp(self):
        #mock vuln for testing
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

    def test_callback_plain(self):
        self.spider.vuln.parse_mode = 'plain'
        callback = self.spider.callback()
        self.assertEqual(callback.__name__, 'parse_plain')

    def test_start_requests(self):
        self.spider.vuln.parse_mode = 'html'
        request = next(self.spider.start_requests())
        self.assertEqual(request.url, self.spider.vuln.base_url)

    def test_parse_html(self):
        vulns = ['CVE-2016-4796', 'CVE-2018-20406', 'CVE-2019-10017']
        self.spider.vuln.parse_mode = 'html'
        self.spider.vuln.xpaths = ["//div[contains(@class, 'references')]" \
                                   "//ul//li/text()"]
        response = fake_response_from_file('./mocks/2.html')
        item = next(self.spider.parse_html(response))
        for vuln in vulns:
            self.assertIn(vuln, item['equivalent_vulns'])

    @mock.patch('patchfinder.spiders.vuln_spider.utils.parse_file_by_block')
    @mock.patch('patchfinder.spiders.vuln_spider.utils.write_response_to_file')
    def test_parse_plain_as_per_block(self,
                                      mock_write_response_method,
                                      mock_parse_file_method):
        self.spider.vuln.as_per_block = True
        self.spider.vuln.start_block = None
        self.spider.vuln.end_block = None
        self.spider.vuln.search_params = None
        equivalent_vulns = ['CVE-2019-11707 CVE-2019-11708']
        mock_parse_file_method.return_value = [equivalent_vulns]
        response = fake_response_from_file('./mocks/mock_debian_dsa_list')
        item = next(self.spider.parse_plain(response))
        mock_write_response_method.assert_called_once()
        mock_parse_file_method.assert_called_with(settings.TEMP_FILE,
                                                  self.spider.vuln.start_block,
                                                  self.spider.vuln.end_block,
                                                  self.spider.vuln.search_params)
        self.assertEqual(item['equivalent_vulns'],
                         equivalent_vulns)


if __name__ == '__main__':
    unittest.main()
