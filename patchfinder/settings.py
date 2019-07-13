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
