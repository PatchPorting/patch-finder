from urllib.parse import urlparse
from scrapy.http import Request
from scrapy.linkextractors.lxmlhtml import LxmlLinkExtractor
import scrapy
import re
from patchfinder.debian import DebianParser
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

    deny_pages = {'github.com': [r'github\.com/[^/]+/[^/]+$',
                                 r'/blob/',
                                 r'/releases$',
                                 r'/releases/.+?/[^/]+$']}
    deny_domains = settings.DENY_DOMAINS
    important_domains = settings.IMPORTANT_DOMAINS
    patch_limit = settings.PATCH_LIMIT
    debian = settings.PARSE_DEBIAN
    allowed_keys = {'deny_domains', 'important_domains', 'patch_limit',
                    'debian'}


    def __init__(self, *args, **kwargs):
        self.name = 'default_spider'
        self.vuln_id = kwargs.get('vuln').vuln_id
        self.start_urls = kwargs.get('vuln').entrypoint_URLs
        self.patches = []
        self.__dict__.update((k, v) for k, v in kwargs.items() \
                             if k in self.allowed_keys)
        super(DefaultSpider, self).__init__(*args, **kwargs)


    def start_requests(self):
        for url in self.start_urls:
            if url.startswith('https://security-tracker.debian.org'):
                if self.debian:
                    yield Request(url, callback=self.parse_debian)
            else:
                yield Request(url, callback=self.parse)


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
        links = LxmlLinkExtractor(deny_domains=self.deny_domains,
                                  restrict_xpaths=xpaths) \
                                          .extract_links(response)
        for link in links:
            link = response.urljoin(link.url[0:])
            patch_link = entrypoint.is_patch(link)
            if patch_link:
                if patch_link not in self.patches:
                    divided_links['patch_links'].append(patch_link)
            elif self.allow_page(link):
                divided_links['links'].append(link)
        return divided_links


    def parse_debian(self, response):
        """The parse method for Debian.

        The DebianParser class' parse method is called for retrieving patches
        from Debian.

        Args:
            response: The Response object sent by Scrapy.
        """
        debian_parser = DebianParser()
        patches = debian_parser.parse(self.vuln_id)
        for patch in patches:
            if len(self.patches) < self.patch_limit:
                self.add_patch(patch['patch_link'])
                yield patch


    def parse(self, response):
        """The default parse method.

        If a url in start_urls does not need a separate parser, this
        method is called. The links from the response body are extracted first.
        The patch links are added to the retrieved patches list. The non-patch
        links are crawled. This recursive process goes on till the DEPTH_LIMIT
        is reached.

        Args:
            response: The Response object sent by Scrapy.
        """
        links = self.extract_links(response)
        for link in links['patch_links']:
            if len(self.patches) < self.patch_limit:
                patch = items.Patch()
                patch['patch_link'] = link
                patch['reaching_path'] = response.url
                self.add_patch(link)
                yield patch
        for link in links['links']:
            if len(self.patches) < self.patch_limit:
                priority = self.domain_priority(link)
                yield Request(link, callback=self.parse, priority=priority)


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


    def allow_page(self, url):
        """Determine if url is for an allowed page"""
        domain = urlparse(url).hostname
        if domain in self.deny_pages:
            deny_pages = self.deny_pages[domain]
            for page in deny_pages:
                page = re.compile(page)
                if page.search(url):
                    return False
            return True
        return True


    def add_patch(self, patch_link):
        self.patches.append(patch_link)
