import unittest
import patchfinder.context as context
import patchfinder.spiders.default_spider as default_spider
from scrapy.crawler import CrawlerProcess

class TestSpider(unittest.TestCase):
    """Test Class for spiders"""

    def test_spider_crawl(self):
        vuln = context.create_vuln('CVE-2016-4796')
        process = CrawlerProcess({
            'USER_AGENT': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)',
            'ITEM_PIPELINES': {
                'patchfinder.spiders.pipelines.PatchPipeline': 300
            },
            'DEPTH_LIMIT': 1,
            'LOG_ENABLED': False
        })
        process.crawl(default_spider.DefaultSpider, vuln=vuln)
        process.start()


if __name__ == '__main__':
    unittest.main()
