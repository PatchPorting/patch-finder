import re
import logging
from scrapy.http import Request
from scrapy.exceptions import IgnoreRequest

logger = logging.getLogger(__name__)


class DepthResetMiddleware:
    def process_spider_output(self, response, result, spider):
        """Reset the depth to 0 for requests.

        For any request with 'reset_depth' as True in its meta and 'depth' in
        its meta, its depth is set to 0.

        Yields:
            Objects from the spider's results.
        """
        for obj in result:
            if not isinstance(obj, Request):
                yield obj
                continue
            if (
                "depth" in obj.meta
                and "reset_depth" in obj.meta
                and obj.meta["reset_depth"]
            ):
                obj.meta["depth"] = 0
            yield obj


class ContentTypeFilterDownloaderMiddleware:
    @staticmethod
    def is_valid_response(allowed_content_types, content_type):
        """bool: Check if content-type is allowed."""
        if any(
            re.search(pattern, content_type)
            for pattern in allowed_content_types
        ):
            return True
        return False

    def process_response(self, request, response, spider):
        """Process response content-type to determine if response should be
        allowed.

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
