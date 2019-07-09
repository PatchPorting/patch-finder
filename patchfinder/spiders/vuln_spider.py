import os
import scrapy
from scrapy.http import Request
import patchfinder.utils as utils

class VulnSpider(scrapy.Spider):

    def __init__(self, vuln):
        self.vuln = vuln

    def start_requests(self):
        callback = self.callback()
        if callback:
            yield Request(self.vuln.base_url, callback=callback)

    #NOTE: This could also be achieved by checking content type of the response
    #      instead of passing parse_mode from the vuln.
    def callback(self):
        callback = None
        if self.vuln.parse_mode == 'html':
            callback = self.parse_html
        elif self.vuln.parse_mode == 'json':
            callback = self.parse_json
        elif self.vuln.parse_mode == 'plain':
            callback = self.parse_plain
        return callback

    def parse_html(self, response):
        for xpath in self.vuln.xpaths:
            equivalent_vulns = response.xpath(xpath).extract()
            yield {
                'equivalent_vulns': equivalent_vulns
            }

    def parse_plain(self, response):
        pass

    def parse_json(self, response):
        pass
