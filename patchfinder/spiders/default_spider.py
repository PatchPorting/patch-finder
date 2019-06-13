import scrapy
from scrapy.http import Request
from urllib.parse import urlparse
import patchfinder.spiders.items as items
import patchfinder.entrypoint as entrypoint
from patchfinder.debian import DebianParser
import re

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
        self.vuln_id = kwargs.get('vuln').vuln_id
        self.start_urls = kwargs.get('vuln').entrypoint_URLs
        self.patches = []
        super(DefaultSpider, self).__init__(*args, **kwargs)

    def start_requests(self):
        for url in self.start_urls:
            if url.startswith('https://security-tracker.debian.org'):
                yield Request(url, callback=self.parse_debian)
            else:
                yield Request(url, callback=self.parse)

    def parse_debian(self, response):
        debian_parser = DebianParser()
        patches = debian_parser.parse(self.vuln_id)
        for patch in patches:
            yield patch

    def parse(self, response):
        xpaths = entrypoint.get_xpath(response.url)
        for xpath in xpaths:
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

    def link_is_valid(self, link):
        if re.match(r'^http', link):
            return True
        return False

    def add_patch(self, patch_link):
        self.patches.append(patch_link)
