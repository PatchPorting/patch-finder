import scrapy
from scrapy.spiders import CrawlSpider
from scrapy.http import Request
import sys
import os
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/..')
import entrypoint
import context

class DefaultSpider(scrapy.Spider):

    def __init__(self, vuln, recursion_limit=0):
        self.name = 'default_spider'
        self.recursion_limit = recursion_limit
        self.entrypoints = vuln.entrypoints
        self.visited_urls = []
        self.entrypoint_stack = []
        self.patches = []
        self.current_path = []

    def start_requests(self):
        for entrypoint in self.entrypoints:
            for url in entrypoint.urls:
                yield Request(url, callback=self.parse)

    def parse(self, response):
        links = response.css('a::attr(href)').extract()
        for link in links:
            if entrypoint.is_patch(link):
                if not any(x.patch_link is link for x in self.patches):
                    self.add_patch(link)

    def add_to_path(self, url):
        self.current_path.append(url)

    def pop_from_path(self, url):
        self.current_path.pop()

    def add_patch(self, patch_link):
        self.patches.append(context.Patch(self.current_path, patch_link))
