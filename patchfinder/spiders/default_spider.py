"""Module used for the scraping and patch finding.

This module provides a Scrapy Spider to facilitate patch finding.

Attributes:
    logger: Module level logger.
"""
import logging
from urllib.parse import urlparse

from scrapy.http import Request
from scrapy.linkextractors.lxmlhtml import LxmlLinkExtractor

import patchfinder.context as context
import patchfinder.spiders.items as items
from patchfinder.resource import Resource, is_patch
from patchfinder.settings import PatchfinderSettings
from .base_spider import BaseSpider

logger = logging.getLogger(__name__)


class DefaultSpider(BaseSpider):
    """Scrapy Spider to extract patches. Inherits from BaseSpider.

    If given a CVE as a vulnerability, the spider crawls each of its entrypoint
    URLs and extracts patches/follows links found. For a generic vulnerability,
    i.e. a vulnerability that is not a CVE, the spider determines its aliases
    (which would be CVEs) and crawls their entrypoint URLs. Scraped patches
    are fed to the PatchPipeline. Any links that are found are followed if the
    depth limit is not reached.

    Attributes:
        vuln (Vulnerability): The vulnerability for which patches are to be found.
        patches (list[str]): A list of patch links the spider has found.
        deny_domains (list[str]): A list of domains to deny crawling links of.
        important_domains (list[str]): A list of domains with higher crawling
            priority.
        patch_limit (int): A threshold for the number of patches to collect.
        allowed_keys (set[str]): A set of allowed keys for initialization.
        debian (bool): Boolean value to call the Debian parser.
    """

    def __init__(self, **kwargs):
        self.patches = []
        if "vuln" in kwargs:
            self.set_context(kwargs.get("vuln"))
        settings = kwargs.get("settings", None)
        if not settings:
            settings = PatchfinderSettings()
        self.deny_pages = settings["DENY_PAGES"]
        self.deny_domains = settings["DENY_DOMAINS"]
        self.important_domains = settings["IMPORTANT_DOMAINS"]
        self.patch_limit = settings["PATCH_LIMIT"]
        self.debian = settings["PARSE_DEBIAN"]
        self.patch_find_meta = settings["PATCH_FIND_META"]
        self._processed_vulns = set()
        self.vuln_request_meta = self.patch_find_meta.copy()
        self.vuln_request_meta["reset_depth"] = True
        super(DefaultSpider, self).__init__("default_spider", settings=settings)

    def start_requests(self):
        """Generates initial requests.

        If the given vulnerability is generic, a request for the vulnerability's
        base URL is yielded. Else, requests for the vulnerability's entrypoint
        URLs are yielded.

        Yields:
            scrapy.http.Request: Initial requests.
        """
        if isinstance(self.vuln, context.GenericVulnerability):
            self._processed_vulns.add(self.vuln.vuln_id)
            yield Request(
                self.vuln.base_url,
                callback=self.determine_aliases,
                meta={"reset_depth": True},
            )
        else:
            yield from self._generate_requests_for_vuln(
                self.vuln, meta=self.patch_find_meta
            )

    def set_context(self, vuln):
        """Set the context of the spider

        Args:
            vuln (Vulnerability): A Vulnerability instance.
        """
        self.vuln = vuln
        self.cves = set()

    def determine_aliases(self, response):
        """Determine aliases for a vulnerability.

        Aliases for a vulnerability are determined by scraping the data from the
        response. The given response is for the base URL of the vulnerability.
        Aliases that are CVEs are set in the spiders' instance. Aliases that are
        generic are run through the method themselves to determine their CVE
        aliases. Once a complete set of aliases is determined, requests for the
        aliases' entrypoint URLs is generated.

        Args:
            response (scrapy.http.Response): Response object for the
                vulnerability's base URL.

        Yields:
            scrapy.http.Request: Requests for the found aliases' entrypoint
                URLs and for found generic vulnerabilities' base URLs.
        """
        aliases = context.create_vulns(*list(self.parse(response)))
        for alias in aliases:
            if alias.vuln_id in self._processed_vulns:
                continue
            if isinstance(alias, context.GenericVulnerability):
                yield Request(
                    alias.base_url,
                    callback=self.determine_aliases,
                    meta={"reset_depth": True},
                )
            else:
                logger.info("Alias discovered: %s", alias.vuln_id)
                self.cves.add(alias)
                yield from self._generate_requests_for_vuln(
                    alias, meta=self.vuln_request_meta
                )
            self._processed_vulns.add(alias.vuln_id)

    def _generate_requests_for_vuln(self, vuln, meta=None):
        for url in vuln.entrypoint_urls:
            yield Request(url, callback=self.parse, meta=meta)

    def _generate_items_and_requests(self, response):
        """Generate items and requests for a given response.

        If the find_patches argument is passed in the response's metadata, i.e.,
        if the spider is to be used as a patch finder, the patches and requests
        for the response are generated. Else, the necessary data is scraped from
        the response and generated.

        Args:
            response (scrapy.http.Response): A Response object.

        Yields:
            (str or scrapy.Item or scrapy.http.Request): If find_patches in
                the response meta is True, patch items and requests, else data,
                i.e., strings from the response.
        """
        if response.meta.get("find_patches"):
            yield from self._patches_and_requests(response)
        else:
            yield from self._scrape(response)

    def _patches_and_requests(self, response):
        """Extract patch links and links to crawl from a response.

        The links from the response body are extracted first.
        The patch links are added to the retrieved patches list.
        Corresponding items and requests are generated from these links.
        If the number of patches found is equal to the patch_limit,
        no more requests or items are generated.

        Args:
            response (scrapy.http.Response): The Response object sent by Scrapy.

        Yields:
            (scrapy.Item or scrapy.http.Request):
                Items/Requests scraped from the response.
        """
        links = self._extract_links(response)
        for link in links["patch_links"]:
            if len(self.patches) < self.patch_limit:
                if link not in self.patches:
                    self._add_patch(link)
                    patch = self._create_patch_item(link, response.url)
                    yield patch
        for link in links["links"]:
            if len(self.patches) < self.patch_limit:
                priority = self._domain_priority(link)
                yield Request(
                    link,
                    meta=self.patch_find_meta,
                    callback=self.parse,
                    priority=priority,
                )

    # TODO: Handle www. case here. In fact, create a method to return
    #      domain name such that all corner cases are handled.
    def _domain_priority(self, url):
        """Returns a priority for a url.

        The URL's domain is checked for in the important domains list. If found,
        a relatively higher priority is returned, i.e. 1. Else a relatively
        lower priority i.e. 0 is returned.

        Args:
            url (str): The URL for which the priority is to be determined.

        Returns:
            int: 1 if the url belongs to an important domain, 0 otherwise.
        """
        domain = urlparse(url).hostname
        if domain in self.important_domains:
            return 1
        return 0

    def _extract_links(self, response, divide=True):
        """
        Extract links from a response and divide them into patch and
        non-patch links.

        Links are extracted from the Response body. These are extracted from
        the relevant xpath(s) of the page. Links of domains in the deny_domains
        list are ignored. The extracted links are then divided into patch links
        and non-patch links.

        Args:
            response (scrapy.http.Response):
                The Response object used to extract links from.
            divide (bool): If True, the links are to be divided into patch and
                non-patch links.

        Returns:
            (dict{str: list[str]} or list[str]):
                If divide is True, a dictionary of patch and non-patch links,
                else a list of links.
        """
        xpaths = Resource.get_resource(response.url).links_xpaths
        links = LxmlLinkExtractor(
            deny=self.deny_pages,
            deny_domains=self.deny_domains,
            restrict_xpaths=xpaths,
        ).extract_links(response)
        if divide:
            return self._divide_links(response, links)
        return [link.url for link in links]

    @staticmethod
    def _divide_links(response, links):
        """Divide links into patch links and non patch links

        Args:
            response (scrapy.http.Response): The response from which the links
                are extracted
            links (list[scrapy.link.Link]): The list of links extracted

        Returns:
            dict{str: list[str]}:
                A dictionary of links divided into patch and non-patch links
        """
        divided_links = {"patch_links": [], "links": []}
        for link in links:
            link = response.urljoin(link.url[0:])
            patch_link = is_patch(link)
            if patch_link:
                divided_links["patch_links"].append(patch_link)
            else:
                divided_links["links"].append(link)
        return divided_links

    @staticmethod
    def _create_patch_item(patch_link, reaching_path):
        patch = items.Patch()
        patch["patch_link"] = patch_link
        patch["reaching_path"] = reaching_path
        return patch

    def _add_patch(self, patch_link):
        self.patches.append(patch_link)
