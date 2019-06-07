import scrapy
from scrapy.spiders import CrawlSpider
from scrapy.http import Request
import patchfinder.spiders.items as items
import sys
import os
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/..')
import entrypoint
import context

class DefaultSpider(scrapy.Spider):
    """Scrapy Spider to extract patches

    Inherits from scrapy.Spider
    This spider would run by default

    Attributes:
        name: Name of the spider
        recursion_limit: The recursion depth the spider would go to
        entrypoints: A list of entrypoints the spider will crawl
        visited_urls: A list of pages visited by the spider
        patches: A list of patch links the spider has found
        current_path: The current path of the spider from the root
    """

    def __init__(self, vuln, recursion_limit=0):
        self.name = 'default_spider'
        self.recursion_limit = recursion_limit
        self.entrypoints = vuln.entrypoints
        self.visited_urls = []
        self.patches = []
        self.current_path = []

    def start_requests(self):
        for entrypoint in self.entrypoints:
            for url in entrypoint.urls:
                self.current_url = url
                yield Request(url, callback=self.parse)

    def parse(self, response):
        self.add_to_path(self.current_url)
        links = response.css('a::attr(href)').extract()
        for link in links:
            if entrypoint.is_patch(link):
                if not link in self.patches:
                    patch = items.Patch()
                    patch['patch_link'] = link
                    patch['reaching_path'] = self.current_path
                    yield patch
                    self.add_patch(link)
        self.pop_from_path()

    def add_to_path(self, url):
        self.current_path.append(url)

    def pop_from_path(self):
        self.current_path.pop()

    def add_patch(self, patch_link):
        self.patches.append(patch_link)
