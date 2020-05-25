import logging
import re

from scrapy.exceptions import IgnoreRequest
from scrapy.http import Request

logger = logging.getLogger(__name__)


class DepthResetMiddleware:
    """A spider middleware to reset the depth of a request.

    For operation of the spider, a depth limit is necessary. At the same time,
    there are cases where the depth should not be tracked. For some requests,
    all that is needed is the response without having to worry about hitting
    the depth limit and having requests rejected by Scrapy's DepthMiddleware.

    Thus, in the same spider instance, it is necessary to mind the depth limit
    while in some cases to not care about it. Such a case is finding aliases
    of a generic vulnerability identifier.
    """

    def process_spider_output(self, result, **kwargs):
        """Reset the depth to 0 for requests.

        For any request with 'reset_depth' as True in its meta and 'depth' in
        its meta, its depth is set to 0.

        Args:
            result: The output of the spider's parse callback.

        Returns:
            list[scrapy.Item, scrapy.http.Request]:
                Objects from the spider's results.
        """

        def _filter(request):
            if not isinstance(request, Request):
                return request
            if (
                    "depth" in request.meta
                    and "reset_depth" in request.meta
                    and request.meta["reset_depth"]
            ):
                request.meta["depth"] = 0
            return request

        return (r for r in result or () if _filter(r))


class ContentTypeFilterDownloaderMiddleware:
    """Downloader middleware to filter/allow responses based on content-type.

    Certain responses cannot be parsed by Scrapy because of their content-type.
    The last thing you need is stumbling upon a URL that gives a 100 MB response
    which can't be parsed because it isn't text.

    Thus, filtering responses based on their content-type is an efficient way to
    avoid responses you don't want to parse. This middleware checks the
    response's headers first. If it finds an allowed content-type, the response
    is allowed.
    """

    @staticmethod
    def _is_valid_response(allowed_content_types, content_type):
        """bool: Check if content-type is allowed."""
        return any(
            re.search(pattern, content_type)
            for pattern in allowed_content_types
        )

    def process_response(self, response, spider, **kwargs):
        """Process response content-type to determine if it should be allowed.

        If the response has no Content-Type or if does not match the
        regular expression of any of the allowed content types, drops it.

        Returns:
            scrapy.http.Response: The response object.

        Raises:
            IgnoreRequest: If response content-type does not exist or is
                not allowed.
        """
        content_type = response.headers.get("Content-Type", None)
        if not content_type:
            raise IgnoreRequest(
                "Response for %s does not have Content-Type in headers, ignoring."
                % (response.url)
            )
        content_type = content_type.decode()
        if self._is_valid_response(spider.allowed_content_types, content_type):
            return response
        raise IgnoreRequest(
            "Content-Type %s not allowed, ignoring response for %s."
            % (content_type, response.url)
        )
