from scrapy.linkextractors.lxmlhtml import LxmlLinkExtractor
from scrapy.utils.python import unique as unique_list
from scrapy.utils.response import get_base_url
import patchfinder.entrypoint as entrypoint
import re


class PatchfinderLinkExtractor(LxmlLinkExtractor):
    def extract_links(self, response):
        base_url = get_base_url(response)
        entrypoint_obj = entrypoint.get_entrypoint_from_url(response.url)
        restrict_xpaths = entrypoint_obj.xpaths
        if restrict_xpaths:
            docs = [
                subdoc for x in restrict_xpaths for subdoc in response.xpath(x)
            ]
        else:
            docs = [response.selector]
        all_links = []
        for doc in docs:
            links = self._extract_links(
                doc, response.url, response.encoding, base_url
            )
            all_links.extend(self._process_links(links))
        return unique_list(all_links)
