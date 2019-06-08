import scrapy
from scrapy.spiders import CrawlSpider
from scrapy.http import Request
import patchfinder.spiders.items as items
import re
import sys
import os
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/..')
import entrypoint
import context

class DefaultSpider(CrawlSpider):
    """Scrapy Spider to extract patches

    Inherits from scrapy.spiders.CrawlSpider
    This spider would run by default

    Attributes:
        name: Name of the spider
        recursion_limit: The recursion depth the spider would go to
        entrypoints: A list of entrypoints the spider will crawl
        visited_urls: A list of pages visited by the spider
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
                self.last_entrypoint = e
                yield Request(e.url, callback=self.parse)

    def parse(self, response):
        self.add_to_path(response.url)
        self.add_to_visited_urls(response.url)
        links = response.xpath(self.last_entrypoint.xpath).extract()
        for link in links:
            if entrypoint.is_patch(link) and link not in self.patches:
                patch = items.Patch()
                patch['patch_link'] = link
                patch['reaching_path'] = self.current_path
                self.add_patch(link)
                yield patch
            elif not (len(self.current_path) >= self.recursion_limit) \
                    and self.url_is_valid(link):
                link = self.format_url(link)
                if link not in self.visited_urls:
                    self.last_entrypoint = \
                            entrypoint.get_entrypoint_from_url(link)
                    yield Request(link, callback=self.parse)
        self.pop_from_path()

    def format_url(self, url):
        if re.match(r'^/', url):
            url = 'https://' + self.last_entrypoint.url.split('/')[2] + url
        return url

    def url_is_valid(self, url):
        if re.match(r'^\#', url):
            return False
        return True

    def add_to_path(self, url):
        self.current_path.append(url)

    def pop_from_path(self):
        self.current_path.pop()

    def add_patch(self, patch_link):
        self.patches.append(patch_link)

    def add_to_visited_urls(self, url):
        self.visited_urls.append(url)
