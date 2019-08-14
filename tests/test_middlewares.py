"""Tests for spider and downloader middlewares."""
import unittest

from scrapy.exceptions import IgnoreRequest
from scrapy.http import Request

import patchfinder.spiders.default_spider as default_spider
import patchfinder.spiders.middlewares as middlewares
from tests import fake_response


class TestMiddlewares(unittest.TestCase):
    """Test Class for Spider and Downloader middlewares."""

    def test_content_type_filter_for_response_with_allowed_content_type(self):
        """For an allowed content-type, the middleware should return response.

        Tests:
            patchfinder.spiders.middlewares.ContentTypeFilterDownloaderMiddleware
        """
        spider = default_spider.DefaultSpider()
        spider.allowed_content_types = [r"text/html"]
        middleware = middlewares.ContentTypeFilterDownloaderMiddleware()
        response = fake_response(
            url="https://foo", content_type=b"text/html; charset=utf-8"
        )
        self.assertEqual(
            middleware.process_response(response=response, spider=spider),
            response,
        )

    def test_content_type_filter_for_response_with_unallowed_content_type(self):
        """For an unallowed content-type, the middleware should raise exception.

        Tests:
            patchfinder.spiders.middlewares.ContentTypeFilterDownloaderMiddleware
        """
        spider = default_spider.DefaultSpider()
        spider.allowed_content_types = [r"text/html"]
        middleware = middlewares.ContentTypeFilterDownloaderMiddleware()
        response = fake_response(
            url="https://foo",
            content_type=b"application/xhtml+xml; charset=utf-8",
        )
        with self.assertRaises(IgnoreRequest):
            middleware.process_response(response=response, spider=spider)

    def test_content_type_filter_for_response_with_no_content_type(self):
        """For response with no content-type, middleware should raise exception.

        Tests:
            patchfinder.spiders.middlewares.ContentTypeFilterDownloaderMiddleware
        """
        spider = default_spider.DefaultSpider()
        spider.allowed_content_types = [r"text/html"]
        middleware = middlewares.ContentTypeFilterDownloaderMiddleware()
        response = fake_response(url="https://foo")
        with self.assertRaises(IgnoreRequest):
            middleware.process_response(response=response, spider=spider)

    def test_depth_reset_middleware_with_reset_depth_as_true(self):
        """The middleware should generate the request with depth as 0.

        Tests:
            patchfinder.spiders.middlewares.DepthResetMiddleware
        """
        middleware = middlewares.DepthResetMiddleware()
        request = Request(
            url="https://foo", meta={"depth": 1, "reset_depth": True}
        )
        result = next(middleware.process_spider_output(result=[request]))
        self.assertEqual(result.meta["depth"], 0)

    def test_depth_reset_middleware_with_reset_depth_as_false(self):
        """The middleware should generate the request unchanged.

        Tests:
            patchfinder.spiders.middlewares.DepthResetMiddleware
        """
        middleware = middlewares.DepthResetMiddleware()
        request = Request(
            url="https://foo", meta={"depth": 1, "reset_depth": False}
        )
        result = next(middleware.process_spider_output(result=[request]))
        self.assertEqual(result.meta["depth"], 1)

    def test_depth_reset_middleware_with_reset_depth_not_in_meta(self):
        """The middleware should generate the request unchanged.

        Tests:
            patchfinder.spiders.middlewares.DepthResetMiddleware
        """
        middleware = middlewares.DepthResetMiddleware()
        request = Request(url="https://foo", meta={"depth": 1})
        result = next(middleware.process_spider_output(result=[request]))
        self.assertEqual(result.meta["depth"], 1)

    def test_depth_reset_middleware_with_depth_not_in_meta(self):
        """The middleware should generate the request unchanged.

        Tests:
            patchfinder.spiders.middlewares.DepthResetMiddleware
        """
        middleware = middlewares.DepthResetMiddleware()
        request = Request(url="https://foo", meta={"reset_depth": True})
        result = next(middleware.process_spider_output(result=[request]))
        self.assertNotIn("depth", result.meta)


if __name__ == "__main__":
    unittest.main()
