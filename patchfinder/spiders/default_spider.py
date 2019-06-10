import scrapy
from scrapy.spiders import CrawlSpider, Rule
from scrapy.http import Request
from urllib.parse import urlparse
import patchfinder.spiders.items as items
from patchfinder.spiders.patchfinder_linkextractor import PatchfinderLinkExtractor
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

    rules = [Rule(PatchfinderLinkExtractor(deny=(r'commit')), callback='parse_items', follow=True)] 

    def __init__(self, *args, **kwargs):
        self.name = 'default_spider'
        entrypoints = kwargs.get('vuln').entrypoints
        self.start_urls = []
        for e in entrypoints:
            self.start_urls.append(e.url)
        self.visited_urls = []
        self.patches = []
        self.current_path = []
        super(DefaultSpider, self).__init__(*args, **kwargs)

    def parse_items(self, response):
        entrypoint_obj = entrypoint.get_entrypoint_from_url(response.url)
        for xpath in entrypoint_obj.xpaths:
            links = response.xpath(xpath+'/@href').extract()
            for link in links:
                if entrypoint.is_patch(link) and link not in self.patches:
                    patch = items.Patch()
                    patch['patch_link'] = link
                    patch['reaching_path'] = self.current_path
                    self.add_patch(link)
                    yield patch
        del entrypoint_obj

    def add_to_path(self, link):
        self.current_path.append(link)

    def pop_from_path(self):
        self.current_path.pop()

    def add_patch(self, patch_link):
        self.patches.append(patch_link)

    def add_to_visited_urls(self, url):
        self.visited_urls.append(url)
