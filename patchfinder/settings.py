"""Settings used by the patch finder.

These settings are specific to Scrapy as well as to the patch-finder and its
behaviour.

Attributes:
    USER_AGENT (str): The user agent used by the spider while crawling.
    DENY_DOMAINS (list[str]): A list of domains for which links are not to be scraped or
        followed.
    IMPORTANT_DOMAINS (list[str]): A list of domains to prioritize crawling.
    PATCH_LIMIT (int): The maximum number of patches to scrape.
    DEPTH_LIMIT (int): The maximum depth the spider should go to while crawling, i.e.,
        while following links.
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
    REQUEST_META: A base meta dictionary to be used by every request yielded
        by the spider.
    PATCH_FIND_META: A meta dictionary to be used by the spider in finding
        patches and following links. This dictionary extends on REQUEST_META.
    NORMAL_META: A meta dictionary to be used by the spider in normal scraping.
        This dictionary extends on REQUEST_META.
    EXTENSIONS: A dictionary of extensions to be used by Scrapy.
"""
import os

USER_AGENT = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)"
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
DEPTH_LIMIT = 1
PARSE_DEBIAN = True
DOWNLOAD_DIRECTORY = "./cache/"
TEMP_FILE = os.path.join(DOWNLOAD_DIRECTORY, "temp_file")
PATCHES_JSON = "./patches.json"
ALLOWED_CONTENT_TYPES = [r"text/html", r"text/plain", r"application/json"]
REQUEST_META = {"dont_redirect": True, "handle_httpstatus_list": [301, 302]}
PATCH_FIND_META = dict(REQUEST_META)
PATCH_FIND_META["find_patches"] = True
NORMAL_META = dict(REQUEST_META)
NORMAL_META["find_patches"] = False
EXTENSIONS = {
    "scrapy.extensions.telnet.TelnetConsole": None,
    "scrapy.extensions.corestats.CoreStats": None,
    "scrapy.extensions.memusage.MemoryUsage": None,
    "scrapy.extensions.logstats.LogStats": None,
}
