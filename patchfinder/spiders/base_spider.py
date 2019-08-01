"""Provides Base Scrapy spider.

Attributes:
    logger: Module level logger.
"""
import logging
import json
import scrapy
import patchfinder.context as context
import patchfinder.settings as settings
from patchfinder.entrypoint import Resource
import dicttoxml

logger = logging.getLogger(__name__)


class BaseSpider(scrapy.Spider):
    """Base Scrapy Spider.

    This spider has the functionalities that can be used by successive spiders.
    """

    def parse(self, response):
        parse_callable = self._callback(response)
        if parse_callable:
            yield from parse_callable(response)

    def parse_default(self, response):
        """Default parse method.

        The response is parsed as per the necessary xpath(s).

        Args:
            response: A response object
        """
        yield from self._generate_items_and_requests(response)

    def parse_json(self, response):
        """Parse a JSON response

        The response is converted to XML and then parsed as per the necessary
        xpath(s).

        Args:
            response: The Response object
        """
        response = self._json_response_to_xml(response)
        yield from self._generate_items_and_requests(response)

    @staticmethod
    def _json_response_to_xml(response):
        dictionary = json.loads(response.body)
        xml = dicttoxml.dicttoxml(dictionary)
        return response.replace(body=xml)

    def _generate_items_and_requests(self, response):
        yield from self._scrape(response)

    def _scrape(self, response):
        """Generate items and requests for a given response.

        If the find_patches argument is passed in the response's metadata, i.e.,
        if the spider is to be used as a patch finder, the patches and requests
        for the response are generated. Else, the necessary data is scraped from
        the response and generated.

        Args:
            response: A Response object.
        """
        xpaths = Resource.get_resource(response.url).get_normal_xpaths()
        for xpath in xpaths:
            scraped_items = response.xpath(xpath).extract()
            for item in scraped_items:
                yield item

    def _callback(self, response):
        """Determine the callback method based on a URL

        The callback method can be based on the content-type of the response of
        the URL or on the URL itself, i.e., certain URLs can warrant using a
        different parse method altogether. This method determines the callback
        for a given response.

        Args:
            response: The response for which the callback method is to be
                determined.

        Returns:
            A callback method object
        """
        callback = self._callback_by_url(response)
        if not callback:
            callback = self._callback_by_content(response)
        return callback

    def _callback_by_url(self, response):
        """Set the current callback method for a given URL

        Args:
            url: The URL for which the callback method is to be determined

        Returns:
            A callback method object
        """
        return None

    def _callback_by_content(self, response):
        """Set the current callback method for a given content-type

        Args:
            response: A Response object.

        Returns:
            A callback method object
        """
        callback = None
        content_type = response.headers["Content-Type"].decode()
        if content_type.startswith("application/json"):
            callback = self.parse_json
        else:
            callback = self.parse_default
        return callback
