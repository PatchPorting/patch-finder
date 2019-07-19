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
