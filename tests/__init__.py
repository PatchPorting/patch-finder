import os
from scrapy.http import HtmlResponse, Request
import patchfinder.settings as settings

def fake_response(file_name=None, url=None, meta=None, content_type=None):
    """Create a fake Scrapy HTTP response.

    For the response to have a body to parse, a HTML file name has to be passed.
    If no file name is given, the response is returned with a blank body.

    Args:
        file_name (str): The relative filename from the responses directory,
            but absolute paths are also accepted. Defaults to None.
        url (str): The URL of the response. Defaults to None.
        meta (dict): The meta of the response. Defaults to None.
        content_type (bytes): The content-type of the response. Defaults to None.

    Returns:
        scrapy.http.HtmlResponse:
            A scrapy HTTP response which can be used for unittesting.
    """
    if not url:
        url = "http://www.example.com"

    request = Request(url=url, meta=meta)
    body = b""
    if file_name:
        body = _read_file(file_name)
    response = HtmlResponse(url=url, request=request, body=body)
    if content_type:
        response.headers["Content-Type"] = content_type
    return response


def _read_file(file_name):
    if not file_name[0] == "/":
        mocks_dir = os.path.dirname(os.path.realpath(__file__))
        file_path = os.path.join(mocks_dir, file_name)
    else:
        file_path = file_name
    try:
        mock_file = open(file_path, "r")
        body = mock_file.read().encode()
    finally:
        mock_file.close()
    return body
