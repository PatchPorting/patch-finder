import scrapy
from scrapy.spiders import CrawlSpider
from scrapy.http import Request
import patchfinder.spiders.items as items
import re
import sys
import os
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/..')
import entrypoint

class DefaultSpider(CrawlSpider):
    """Scrapy Spider to extract patches

    Inherits from scrapy.spiders.CrawlSpider
    This spider would run by default

    Attributes:
        name: Name of the spider
        recursion_limit: The recursion depth the spider would go to
        entrypoints: A list of entrypoints the spider will crawl
        visited_links: A list of pages visited by the spider
        patches: A list of patch links the spider has found
        current_path: The current path of the spider from the root
    """

    def __init__(self, vuln, recursion_limit=1):
        self.name = 'default_spider'
        self.recursion_limit = recursion_limit
        self.entrypoints = vuln.entrypoints
        self.visited_urls = []
        self.patches = []
        self.current_path = []

    def start_requests(self):
        for e in self.entrypoints:
            if e.url not in self.visited_urls:
                yield Request(e.url, callback=self.parse)

    def parse(self, response):
        self.add_to_path(response.url)
        self.add_to_visited_urls(response.url)
        entrypoint_obj = entrypoint.get_entrypoint_from_url(response.url)
        for xpath in entrypoint_obj.xpaths:
            links = response.xpath(xpath).extract()
            for link in links:
                if self.link_is_valid(link):
                    if entrypoint.is_patch(link) and link not in self.patches:
                        patch = items.Patch()
                        patch['patch_link'] = link
                        patch['reaching_path'] = self.current_path
                        self.add_patch(link)
                        yield patch
                    elif link not in self.visited_urls:
                        yield Request(link, callback=self.parse)
        del entrypoint_obj
        self.pop_from_path()

    def link_is_valid(self, link):
        if not re.match(r'^http', link):
            return False
        return True

    def add_to_path(self, link):
        self.current_path.append(link)

    def pop_from_path(self):
        self.current_path.pop()

    def add_patch(self, patch_link):
        self.patches.append(patch_link)

    def add_to_visited_urls(self, url):
        self.visited_urls.append(url)
