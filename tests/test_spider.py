import unittest
import patchfinder.context as context
import patchfinder.spiders.default_spider as default_spider
from scrapy.crawler import CrawlerProcess

class TestSpider(unittest.TestCase):
    """Test Class for spiders"""

    def test_spider_init(self):
        vuln = context.create_vuln('CVE-2016-4796')
        spider = default_spider.DefaultSpider(vuln)
        self.assertEqual(spider.recursion_limit, 0)
        self.assertEqual(spider.entrypoints, vuln.entrypoints)

    def test_spider_crawl(self):
        vuln = context.create_vuln('CVE-2016-4796')
        process = CrawlerProcess({
            'USER_AGENT': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)'
        })
        process.crawl(default_spider.DefaultSpider, vuln)
        process.start()


if __name__ == '__main__':
    unittest.main()
