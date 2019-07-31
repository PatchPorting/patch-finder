"""Settings used by the patch finder.

These settings are specific to Scrapy as well as to the patch-finder and its
behaviour.

Attributes:
    USER_AGENT: The user agent used by the spider while crawling.
    DENY_DOMAINS: A list of domains for which links are not to be scraped or
        followed.
    IMPORTANT_DOMAINS: A list of domains to prioritize crawling.
    PATCH_LIMIT: The maximum number of patches to scrape.
    DEPTH_LIMIT: The maximum depth the spider should go to while crawling, i.e.,
        while following links.
    PARSE_DEBIAN: If True, the DebianParser is used while crawling.
    DOWNLOAD_DIRECTORY: Path of directory to use for temporary storage of any
        items downloaded.
    TEMP_FILE: Path to a temporary file used by the spider. This file will only
        be used in certain cases to write a response body for further
        processing.
    PATCHES_JSON: Path or name of the JSON file to be used for storing patches
        found.
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
IMPORTANT_DOMAINS = []
PATCH_LIMIT = 100
DEPTH_LIMIT = 1
PARSE_DEBIAN = True
DOWNLOAD_DIRECTORY = "./cache/"
TEMP_FILE = os.path.join(DOWNLOAD_DIRECTORY, "temp_file")
PATCHES_JSON = "./patches.json"
REQUEST_META = {"dont_redirect": True, "handle_httpstatus_list": [302]}
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
