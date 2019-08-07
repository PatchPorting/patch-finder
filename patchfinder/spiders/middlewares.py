import re
import logging
from scrapy.http import Request
from scrapy.exceptions import IgnoreRequest

logger = logging.getLogger(__name__)


class DepthResetMiddleware:
    def process_spider_output(self, result, **kwargs):
        """Reset the depth to 0 for requests.

        For any request with 'reset_depth' as True in its meta and 'depth' in
        its meta, its depth is set to 0.

        Yields:
            Objects from the spider's results.
        """
        # TODO (jas): do we really need to yield or non-return is an option?.
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
    @staticmethod
    def is_valid_response(allowed_content_types, content_type):
        """bool: Check if content-type is allowed."""
        return any(
            re.search(pattern, content_type)
            for pattern in allowed_content_types
        )

    def process_response(self, response, spider, **kwargs):
        """Process response content-type to determine if response should be
        allowed. If the response has no Content-Type or if does not match the
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
        if self.is_valid_response(spider.allowed_content_types, content_type):
            return response
        raise IgnoreRequest(
            "Content-Type %s not allowed, ignoring response for %s."
            % (content_type, response.url)
        )
