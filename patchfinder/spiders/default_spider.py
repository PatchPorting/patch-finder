from urllib.parse import urlparse
from scrapy.http import Request
from scrapy.linkextractors.lxmlhtml import LxmlLinkExtractor
import scrapy
import re
import patchfinder.parsers as parsers
import patchfinder.spiders.items as items
import patchfinder.entrypoint as entrypoint
import patchfinder.settings as settings

class DefaultSpider(scrapy.Spider):
    """Scrapy Spider to extract patches

    Inherits from scrapy.Spider
    This spider would run by default

    Attributes:
        name: Name of the spider
        vuln_id: The vulnerability ID for which patches are to be found
        recursion_limit: The recursion depth the spider would go to
        patches: A list of patch links the spider has found
        deny_domains: A list of domains to deny crawling links of
        important_domains: A list of domains with higher crawling priority
        patch_limit: A threshold for the number of patches to collect
        allowed_keys: A set of allowed keys for initialization
        debian: Boolean value to call the Debian parser
    """

    deny_pages = [r'github\.com/[^/]+/[^/]+$',
                  r'github\.com/[^/]+/[^/]+/blob/',
                  r'github\.com.+/releases$',
                  r'github\.com.+/releases/.+?/[^/]+$',
                  #homepages
                  r'^https?://[^/]+/?$',
                  #fragmented identifiers
                  r'\#.+$']
    deny_domains = settings.DENY_DOMAINS
    important_domains = settings.IMPORTANT_DOMAINS
    patch_limit = settings.PATCH_LIMIT
    debian = settings.PARSE_DEBIAN
    request_meta = settings.REQUEST_META
    allowed_keys = {'deny_domains', 'important_domains', 'patch_limit',
                    'debian'}


    def __init__(self, *args, **kwargs):
        self.name = 'default_spider'
        if 'vuln' in kwargs:
            self.vuln_id = kwargs.get('vuln').vuln_id
            self.start_urls = kwargs.get('vuln').entrypoint_urls
        else:
            self.vuln_id = None
            self.start_urls = []
        self.patches = []
        self.__dict__.update((k, v) for k, v in kwargs.items() \
                             if k in self.allowed_keys)
        super(DefaultSpider, self).__init__(*args, **kwargs)


    def start_requests(self):
        for url in self.start_urls:
            callback = self.callback(url)
            yield Request(url, meta=self.request_meta, callback=callback)


    def callback(self, url):
        """Return the callback method for a given URL

        Args:
            url: Self explanatory

        Returns:
            A callback method object
        """
        callback = self.parse
        if (url.startswith('https://security-tracker.debian.org')
            and self.debian):
            callback = self.parse_debian
        return callback


    def extract_links(self, response):
        """Extract links from a response and divide them into patch links
        and non-patch links.

        Links are extracted from the Response body. These are extracted from
        the relevant xpath of the page. Links of domains in the deny_domains
        list are ignored. The extracted links are then divided into patch links
        and non-patch links.

        Args:
            response: The Response object used to extract links from.

        Returns:
            A dictionary of links divided into patch and non-patch links.
        """
        divided_links = {'patch_links': [],
                         'links': []}
        xpaths = entrypoint.get_xpath(response.url)
        links = LxmlLinkExtractor(deny=self.deny_pages,
                                  deny_domains=self.deny_domains,
                                  restrict_xpaths=xpaths) \
                                          .extract_links(response)
        for link in links:
            link = response.urljoin(link.url[0:])
            patch_link = entrypoint.is_patch(link)
            if patch_link:
                divided_links['patch_links'].append(patch_link)
            else:
                divided_links['links'].append(link)
        return divided_links


    def parse_debian(self, response):
        """The parse method for Debian.

        The DebianParser class' parse method is called for retrieving patches
        from Debian.

        Args:
            response: The Response object sent by Scrapy.
        """
        parser = parsers.DebianParser()
        patches = parser.parse(self.vuln_id)
        for patch in patches:
            if len(self.patches) < self.patch_limit:
                self.add_patch(patch['patch_link'])
                patch = self._create_patch_item(patch['patch_link'],
                                                patch['reaching_path'])
                yield patch


    def parse(self, response):
        """The default parse method.

        If a url does not need a separate parser, this method is called.
        The links from the response body are extracted first.
        The patch links are added to the retrieved patches list. The non-patch
        links are crawled. This recursive process goes on till the DEPTH_LIMIT
        is reached. If the number of patches found is equal to the patch_limit,
        no more requests or items are generated.

        Args:
            response: The Response object sent by Scrapy.
        """
        links = self.extract_links(response)
        for link in links['patch_links']:
            if len(self.patches) < self.patch_limit:
                if link not in self.patches:
                    self.add_patch(link)
                    patch = self._create_patch_item(link, response.url)
                    yield patch
        for link in links['links']:
            if len(self.patches) < self.patch_limit:
                callback = self.callback(link)
                priority = self.domain_priority(link)
                yield Request(link, meta=self.request_meta,
                              callback=callback, priority=priority)


    #TODO: Handle www. case here. In fact, create a method to return
    #      domain name such that all corner cases are handled.
    def domain_priority(self, url):
        """Returns a priority for a url

        The URL's domain is checked for in the important domains list. If found,
        a relatively higher priority is returned, i.e. 1. Else a relatively
        lower priority i.e. 0 is returned.
        """
        domain = urlparse(url).hostname
        if domain in self.important_domains:
            return 1
        return 0


    def _create_patch_item(self, patch_link, reaching_path):
        patch = items.Patch()
        patch['patch_link'] = patch_link
        patch['reaching_path'] = reaching_path
        return patch


    def add_patch(self, patch_link):
        self.patches.append(patch_link)
