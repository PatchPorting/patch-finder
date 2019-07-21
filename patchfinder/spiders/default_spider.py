import logging
from urllib.parse import urlparse
from scrapy.http import Request
from scrapy.linkextractors.lxmlhtml import LxmlLinkExtractor
import scrapy
from inline_requests import inline_requests
import patchfinder.context as context
import patchfinder.parsers as parsers
import patchfinder.spiders.items as items
import patchfinder.entrypoint as entrypoint
import patchfinder.settings as settings
import patchfinder.utils as utils

logger = logging.getLogger(__name__)


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

    deny_pages = [
        r"github\.com/[^/]+/[^/]+$",
        r"github\.com/[^/]+/[^/]+/blob/",
        r"github\.com.+/releases$",
        r"github\.com.+/releases/.+?/[^/]+$",
        # homepages
        r"^https?://[^/]+/?$",
        # fragmented identifiers
        r"\#.+$",
    ]
    deny_domains = settings.DENY_DOMAINS
    important_domains = settings.IMPORTANT_DOMAINS
    patch_limit = settings.PATCH_LIMIT
    debian = settings.PARSE_DEBIAN
    request_meta = settings.REQUEST_META
    _patch_find_meta = settings.PATCH_FIND_META
    _normal_meta = settings.NORMAL_META
    _allowed_keys = {
        "deny_domains",
        "important_domains",
        "patch_limit",
        "debian",
    }

    def __init__(self, *args, **kwargs):
        self.name = "default_spider"
        self.patches = []
        if "vuln" in kwargs:
            self.vuln = kwargs.get("vuln")
            self.vulns = set()
        self.__dict__.update(
            (k, v) for k, v in kwargs.items() if k in self._allowed_keys
        )
        super(DefaultSpider, self).__init__(*args, **kwargs)

    def start_requests(self):
        if isinstance(self.vuln, context.UnparsableVulnerability):
            yield Request(
                self.vuln.base_url,
                callback=self.determine_aliases,
                meta=self._normal_meta,
            )
        else:
            for url in self.vuln.entrypoint_urls:
                yield Request(
                    url, callback=self.parse, meta=self._patch_find_meta
                )

    def set_context(self, vuln):
        self.vuln = vuln

    @inline_requests
    def determine_aliases(self, response):
        """Determine aliases for a vulnerability.

        Aliases for a vulnerability are determined by scraping the data from the
        response. The given response is for the base URL of the vulnerability.
        Aliases which are parsable are set in the spider's instance. Aliases
        which are unparsable are run through the method themselves to
        determine their parsable vulnerabilities. Once a complete set of
        parsable aliases is found, requests for the aliases' entrypoints is
        generated.

        Args:
            response: Response object for the vulnerability's base URL.
        """
        vulns = set([self.vuln])
        processed_vulns = set()
        while True:
            if not vulns:
                break
            temp_aliases = set()
            for vuln in vulns:
                if vuln.vuln_id in processed_vulns:
                    continue
                if vuln.vuln_id is self.vuln.vuln_id:
                    vuln_response = response
                else:
                    vuln_response = yield Request(vuln.base_url)
                processed_vulns.add(vuln.vuln_id)
                aliases = self.parse(vuln_response)
                for alias in aliases:
                    alias = context.create_vuln(alias)
                    if not alias:
                        continue
                    if isinstance(alias, context.UnparsableVulnerability):
                        temp_aliases.add(alias)
                    else:
                        logger.info("Alias discovered: %s", alias.vuln_id)
                        self.vulns.add(alias)
            vulns = temp_aliases
        yield from self._generate_requests_for_vulns()

    def parse_debian(self, response):
        """The parse method for Debian.

        The DebianParser class' parse method is called for retrieving patches
        from Debian.

        Args:
            response: The Response object sent by Scrapy.
        """
        parser = parsers.DebianParser()
        patches = parser.parse(self.vuln.vuln_id)
        for patch in patches:
            if len(self.patches) < self.patch_limit:
                self._add_patch(patch["patch_link"])
                patch = self._create_patch_item(
                    patch["patch_link"], patch["reaching_path"]
                )
                yield patch

    def parse(self, response):
        parse_callable = self._callback(response)
        if parse_callable:
            yield from parse_callable(response)

    def parse_default(self, response):
        """Default parse method.

        The response is parsed as per the necessary xpath(s).

        Args:
            response: A response object
        """
        yield from self._generate_items_and_requests(response)

    def parse_json(self, response):
        """Parse a JSON response

        The response is converted to XML and then parsed as per the necessary
        xpath(s).

        Args:
            response: The Response object
        """
        response = utils.json_response_to_xml(response)
        yield from self._generate_items_and_requests(response)

    def _generate_requests_for_vulns(self):
        for vuln in self.vulns:
            for url in vuln.entrypoint_urls:
                yield Request(
                    url, callback=self.parse, meta=self._patch_find_meta
                )

    def _generate_items_and_requests(self, response):
        """Generate items and requests for a given response.

        If the find_patches argument is passed in the response's metadata, i.e.,
        if the spider is to be used as a patch finder, the patches and requests
        for the response are generated. Else, the necessary data is scraped from
        the response and generated.

        Args:
            response: A Response object.
        """
        if response.meta.get("find_patches"):
            yield from self._patches_and_requests(response)
        else:
            xpaths = entrypoint.get_xpath(response.url)
            for xpath in xpaths:
                scraped_items = response.xpath(xpath).extract()
                for item in scraped_items:
                    yield item

    def _patches_and_requests(self, response):
        """Extract patch links and links to crawl from a response.

        The links from the response body are extracted first.
        The patch links are added to the retrieved patches list.
        Corresponding items and requests are generated from these links.
        If the number of patches found is equal to the patch_limit,
        no more requests or items are generated.

        Args:
            response: The Response object sent by Scrapy.
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
                    meta=self._patch_find_meta,
                    callback=self.parse,
                    priority=priority,
                )

    def _callback(self, response):
        """Determine the callback method based on a URL

        The callback method can be based on the content-type of the response of
        the URL or on the URL itself, i.e., certain URLs can warrant using a
        different parse method altogether. This method determines the callback
        for a given response.

        Args:
            response: The response for which the callback method is to be
                determined.

        Returns:
            A callback method object
        """
        callback = self._callback_by_url(response)
        if not callback:
            callback = self._callback_by_content(response)
        return callback

    def _callback_by_url(self, response):
        """Set the current callback method for a given URL

        Args:
            url: The URL for which the callback method is to be determined

        Returns:
            A callback method object
        """
        callback = None
        url = response.url
        if (
            url.startswith("https://security-tracker.debian.org")
            and self.debian
        ):
            callback = self.parse_debian
        return callback

    def _callback_by_content(self, response):
        """Set the current callback method for a given content-type

        Args:
            response: A Response object.

        Returns:
            A callback method object
        """
        callback = None
        content_type = response.headers["Content-Type"].decode()
        if content_type.startswith("application/json"):
            callback = self.parse_json
        else:
            callback = self.parse_default
        return callback

    def _extract_links(self, response, divide=True):
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
        xpaths = entrypoint.get_xpath(response.url)
        links = LxmlLinkExtractor(
            deny=self.deny_pages,
            deny_domains=self.deny_domains,
            restrict_xpaths=xpaths,
        ).extract_links(response)
        if divide:
            return self._divide_links(response, links)
        return links

    def _divide_links(self, response, links):
        """Divide links into patch links and non patch links

        Args:
            response: The response from which the links are extracted
            links: The list of links extracted

        Returns:
            A dictionary of links divided into patch and non-patch links
        """
        divided_links = {"patch_links": [], "links": []}
        for link in links:
            link = response.urljoin(link.url[0:])
            patch_link = entrypoint.is_patch(link)
            if patch_link:
                divided_links["patch_links"].append(patch_link)
            else:
                divided_links["links"].append(link)
        return divided_links

    # TODO: Handle www. case here. In fact, create a method to return
    #      domain name such that all corner cases are handled.
    def _domain_priority(self, url):
        """Returns a priority for a url

        The URL's domain is checked for in the important domains list. If found,
        a relatively higher priority is returned, i.e. 1. Else a relatively
        lower priority i.e. 0 is returned.

        Args:
            url: The URL for which the priority is to be determined

        Returns:
            1 if the url belongs to an important domain, 0 otherwise
        """
        domain = urlparse(url).hostname
        if domain in self.important_domains:
            return 1
        return 0

    def _create_patch_item(self, patch_link, reaching_path):
        patch = items.Patch()
        patch["patch_link"] = patch_link
        patch["reaching_path"] = reaching_path
        return patch

    def _add_patch(self, patch_link):
        self.patches.append(patch_link)
