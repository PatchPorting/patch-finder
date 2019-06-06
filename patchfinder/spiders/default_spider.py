from scrapy.Spiders import CrawlSpider
import entrypoint

class DefaultSpider(CrawlSpider):
    
    def __init__(self, context):
        self.entrypoints = context.vuln.entrypoints
        self.recursion_limit = context.recursion_limit
        self.visited_urls = []

