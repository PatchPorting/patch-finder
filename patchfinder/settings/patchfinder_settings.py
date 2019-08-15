"""Settings used by the patch finder.

These settings are specific to the patch-finder and its behaviour.

Attributes:
    DENY_DOMAINS (list[str]): A list of domains for which links are not to be scraped or
        followed.
    IMPORTANT_DOMAINS (list[str]): A list of domains to prioritize crawling.
    PATCH_LIMIT (int): The maximum number of patches to scrape.
    PARSE_DEBIAN (bool): If True, the DebianParser is used while crawling.
    DOWNLOAD_DIRECTORY (str): Path of directory to use for temporary storage of any
        items downloaded.
    TEMP_FILE (str): Path to a temporary file used by the spider. This file will only
        be used in certain cases to write a response body for further
        processing.
    PATCHES_JSON (str): Path or name of the JSON file to be used for storing patches
        found.
    ALLOWED_CONTENT_TYPES (list[str]): A list of regular expressions for allowed
        content-types. Responses obtained by the spider should have content-types
        that match any one of these regular expressions to be parsed. Reponses
        that do not have content-types matching any one of these expressions
        will not be parsed and will be discarded.
    PATCH_FIND_META: A meta dictionary to be used by the spider in finding
        patches and following links.
"""
import os

DENY_DOMAINS = ["facebook.com", "twitter.com"]
DENY_PAGES = [
    r"github\.com/[^/]+/[^/]+$",
    r"github\.com/[^/]+/[^/]+/blob/",
    r"github\.com.+/releases$",
    r"github\.com.+/releases/.+?/[^/]+$",
    # homepages
    r"^https?://[^/]+/?$",
    # fragmented identifiers
    r"\#.+$",
]
IMPORTANT_DOMAINS = []
PATCH_LIMIT = 100
PARSE_DEBIAN = True
DOWNLOAD_DIRECTORY = "./cache/"
TEMP_FILE = os.path.join(DOWNLOAD_DIRECTORY, "temp_file")
PATCHES_JSON = "./patches.json"
ALLOWED_CONTENT_TYPES = [r"text/html", r"text/plain", r"application/json"]
PATCH_FIND_META = {
    "dont_redirect": True,
    "handle_httpstatus_list": [301, 302],
    "find_patches": True,
}
