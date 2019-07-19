import os
import patchfinder.settings as settings
from scrapy.http import HtmlResponse, Request


def fake_response_from_file(file_name, url=None, meta=settings.REQUEST_META):
    """
    Create a Scrapy fake HTTP response from a HTML file

    Args:
        file_name: The relative filename from the responses directory,
            but absolute paths are also accepted.
        url: The URL of the response.

    Returns:
        A scrapy HTTP response which can be used for unittesting.
    """
    if not url:
        url = "http://www.example.com"

    request = Request(url=url, meta=meta)
    if not file_name[0] == "/":
        mocks_dir = os.path.dirname(os.path.realpath(__file__))
        file_path = os.path.join(mocks_dir, file_name)
    else:
        file_path = file_name

    mock_file = open(file_path, "r")
    body = mock_file.read().encode()
    mock_file.close()

    response = HtmlResponse(url=url, request=request, body=body)
    return response
