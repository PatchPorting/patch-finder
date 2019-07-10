import os
import scrapy
from scrapy.http import Request
import patchfinder.utils as utils
import patchfinder.settings as settings

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
        """Return the callback method for a given parse mode

        Returns:
            A callback method object
        """
        callback = None
        if self.vuln.parse_mode == 'html':
            callback = self.parse_html
        elif self.vuln.parse_mode == 'json':
            callback = self.parse_json
        elif self.vuln.parse_mode == 'plain':
            callback = self.parse_plain
        return callback

    def parse_html(self, response):
        """Parse an HTML response

        The HTML response is parsed as per the necessary xpath(s).
        """
        for xpath in self.vuln.xpaths:
            equivalent_vulns = response.xpath(xpath).extract()
            yield {
                'equivalent_vulns': equivalent_vulns
            }

    def parse_plain(self, response):
        """Parse a plain text response

        The plain text response can be parsed as per block as well, which some
        sources such as Debian's CVE/DSA list would require.
        """
        file_name = settings.TEMP_FILE
        utils.write_response_to_file(response, file_name, overwrite=True)
        equivalent_vulns = []
        if self.vuln.as_per_block:
            equivalent_vulns = utils.parse_file_by_block(file_name,
                                                    self.vuln.start_block,
                                                    self.vuln.end_block,
                                                    self.vuln.search_params)
        yield {
            'equivalent_vulns': equivalent_vulns
        }

    def parse_json(self, response):
        response = utils.json_response_to_xml(response)
        for xpath in self.vuln.xpaths:
            equivalent_vulns = response.xpath(xpath)
            yield {
                'equivalent_vulns': equivalent_vulns
            }
