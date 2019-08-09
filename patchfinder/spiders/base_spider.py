"""Provides Base Scrapy spider.

Attributes:
    logger: Module level logger.
"""
import re
import logging
import json
import scrapy
import dicttoxml
from patchfinder.settings import PatchfinderSettings
from patchfinder.entrypoint import Resource

logger = logging.getLogger(__name__)


class BaseSpider(scrapy.Spider):
    """Base Scrapy Spider.

    This spider has functionalities that can be used by successive spiders.

    Attributes:
        name (str): Name of the spider.
        allowed_content_types (list[str]): A list of content-types, responses
            of which should be parsed.
    """

    def __init__(self, name, settings=None):
        if not settings:
            settings = PatchfinderSettings()
        self.allowed_content_types = settings["ALLOWED_CONTENT_TYPES"]
        self.name = name
        super(BaseSpider, self).__init__(name)

    def parse(self, response):
        """Parse the given response.

        The relevant parse callable for the response is determined and items are
        generated from it.

        Args:
            response (scrapy.Response): A response object.

        Yields:
            (str or scrapy.Item or scrapy.http.Request):
                Items/Requests generated from the parse callable.
        """
        parse_callable = self._callback(response)
        if parse_callable:
            yield from parse_callable(response)

    def parse_default(self, response):
        """Default parse method.

        The response is parsed as per the necessary xpath(s).

        Args:
            response (scrapy.http.Response): A response object

        Yields:
            (str or scrapy.Item or scrapy.http.Response):
                Items/Requests generated from the response.
        """
        yield from self._generate_items_and_requests(response)

    def parse_json(self, response):
        """Parse a JSON response.

        The response is converted to XML and then parsed as per the necessary
        xpath(s).

        Args:
            response (scrapy.http.Response): The Response object.

        Yields:
            (str or scrapy.Item or scrapy.http.Request):
                Items/Requests generated from the response.
        """
        response = self._json_response_to_xml(response)
        yield from self._generate_items_and_requests(response)

    @staticmethod
    def _json_response_to_xml(response):
        """Convert a JSON response to XML.

        This enables parsing the JSON with Xpaths.

        Args:
            response (scrapy.http.Response): A response object.

        Returns:
            scrapy.http.Response: The same response with an XML body.
        """
        dictionary = json.loads(response.body.decode())
        xml = dicttoxml.dicttoxml(dictionary)
        return response.replace(body=xml)

    def _generate_items_and_requests(self, response):
        """str: Yields scraped items."""
        yield from self._scrape(response)

    # TODO: Should yield Item objects rather than strings.
    @staticmethod
    def _scrape(response):
        """Scrape a given response.

        Items are scraped from the response w/r/t the response's normal xpaths.
        These items are then yielded.

        Args:
            response (scrapy.http.Response): A Response object.

        Yields:
            str: Items scraped from the response.
        """
        xpaths = Resource.get_resource(response.url).normal_xpaths
        for xpath in xpaths:
            scraped_items = response.xpath(xpath).extract()
            for item in scraped_items:
                yield item

    def _callback(self, response):
        """Returns the callback method for a response.

        The callback method is used to parse the response. It can be based on
        the content-type of the response or on the response URL itself, since
        certain URLs can warrant using a different parse method altogether.

        Args:
            response (scrapy.http.Response): The response for which the
                callable is to be determined.

        Returns:
            callable: A parse callable.
        """
        callback = self._callback_by_url(response)
        if not callback:
            callback = self._callback_by_content(response)
        return callback

    def _callback_by_url(self, response):
        """Returns the parse callable based on the response URL.

        Args:
            response (scrapy.http.Response): The response for which the
                callable is to be determined.

        Returns:
            callable: A parse callable.
        """
        return None

    def _callback_by_content(self, response):
        """Returns the parse callable based on the response's content-type.

        Args:
            response (scrapy.http.Response): A Response object.

        Returns:
            callable: A parse callable.
        """
        content_type = response.headers.get("Content-Type").decode()
        if re.search(r"application/json", content_type):
            callback = self.parse_json
        else:
            callback = self.parse_default
        return callback
