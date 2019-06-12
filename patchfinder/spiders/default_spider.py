import scrapy
from scrapy.http import Request
from urllib.parse import urlparse
import patchfinder.spiders.items as items
import re
import sys
import os
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/..')
import entrypoint

class DefaultSpider(scrapy.Spider):
    """Scrapy Spider to extract patches

    Inherits from scrapy.Spider
    This spider would run by default

    Attributes:
        name: Name of the spider
        recursion_limit: The recursion depth the spider would go to
        entrypoints: A list of entrypoints the spider will crawl
        patches: A list of patch links the spider has found
    """

    def __init__(self, *args, **kwargs):
        self.name = 'default_spider'
        entrypoints = kwargs.get('vuln').entrypoints
        self.start_urls = []
        for e in entrypoints:
            self.start_urls.append(e.url)
        self.patches = []
        super(DefaultSpider, self).__init__(*args, **kwargs)

    def parse(self, response):
        entrypoint_obj = entrypoint.get_entrypoint_from_url(response.url)
        for xpath in entrypoint_obj.xpaths:
            links = response.xpath(xpath+'/@href').extract()
            for link in links:
                link = response.urljoin(link[0:])
                if self.link_is_valid(link):
                    patch_link = entrypoint.is_patch(link)
                    if patch_link:
                        if patch_link not in self.patches:
                            patch = items.Patch()
                            patch['patch_link'] = patch_link
                            patch['reaching_path'] = response.url
                            self.add_patch(patch_link)
                            yield patch
                    else:
                        yield Request(link, callback=self.parse)
        del entrypoint_obj

    def link_is_valid(self, link):
        if re.match(r'^http', link):
            return True
        return False

    def add_patch(self, patch_link):
        self.patches.append(patch_link)
