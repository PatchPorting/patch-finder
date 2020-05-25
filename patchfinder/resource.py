"""Provides URL and Patch provider identification.

This module has classes to identify URLs. The purpose for this identification
is either to determine if a URL is a patch or to determine the xpaths to use
for crawling a page.
"""

import logging
import re

logger = logging.getLogger(__name__)

_PROVIDERS = ["Github", "Gitlab", "Bitbucket", "GitKernel", "Pagure"]


# NOTE: is a singleton pattern called for here?
class Provider:
    """Base Class for a patch Provider.

    A patch provider is a resource that provides patches. These are usually
    web hosting services for version control, for example Github. Patches
    are determined w/r/t Providers, i.e., a link must belong to a Provider
    and conform to the Provider's patch/commit link format to be recognized as a
    patch link. Since most links discovered are in the form of commits, these
    links must be formatted into patch links w/r/t the Provider's patch link
    format.

    Attributes:
        link_components (list[str]): A list of components in a patch link for
            this provider.
        patch_components (list[str]): A list of components in a patch-formatted
            link for this provider.
        patch_format_dict (dict[str, str] or None): A dictionary for formatting
            a link into a patch link. Defaults to {r"/commit/": r"/patch/"}.
    """

    patch_format_dict = {r"/commit/": r"/patch/"}

    def __init__(
        self, link_components, patch_components, patch_format_dict=None
    ):
        self.link_components = link_components
        self.patch_components = patch_components
        if patch_format_dict:
            self.patch_format_dict = patch_format_dict

    def patch_format(self, link):
        """str: Returns a link formatted into a patch link."""
        for i in self.patch_format_dict:
            link = re.sub(i, self.patch_format_dict[i], link)
        return link

    @staticmethod
    def match_all(string, patterns):
        """Match a string with regular expression patterns.

        Args:
            string (str): String to match patterns with.
            patterns (list[str]): A list of regular expression patterns.

        Returns:
            bool: True if string matches with all patterns, False otherwise.
        """
        if all(re.search(x, string) for x in patterns):
            return True
        return False

    def is_patch_link(self, link):
        """bool: Check if 'link' is a patch-formatted link."""
        return Provider.match_all(link, self.patch_components)

    def match_link(self, link):
        """bool: Checks if 'link' belongs to this provider."""
        return Provider.match_all(link, self.link_components)

    @classmethod
    def belongs(cls, link):
        provider = cls()
        if not provider.match_link(link):
            return None
        if not provider.is_patch_link(link):
            link = provider.patch_format(link)
        return link


class Github(Provider):
    """Subclass for GitHub as a Provider."""

    def __init__(self):
        link_components = [r"github\.com", r"/(commit|pull)/"]
        patch_components = [r"\.patch$"]
        patch_format_dict = {r"$": r".patch"}
        super(Github, self).__init__(
            link_components=link_components,
            patch_components=patch_components,
            patch_format_dict=patch_format_dict,
        )


class Pagure(Provider):
    """Subclass for Pagure as a Provider."""

    def __init__(self):
        link_components = [r"pagure\.io", "/c/"]
        patch_components = [r"\.patch$"]
        patch_format_dict = {r"$": r".patch"}
        super(Pagure, self).__init__(
            link_components=link_components,
            patch_components=patch_components,
            patch_format_dict=patch_format_dict,
        )


class Gitlab(Provider):
    """Subclass for Gitlab as a Provider."""

    def __init__(self):
        link_components = [r"gitlab\.com", r"/commit/"]
        patch_components = [r"\.patch$"]
        super(Gitlab, self).__init__(
            link_components=link_components, patch_components=patch_components
        )


class GitKernel(Provider):
    """Subclass for git.kernel.org as a Provider."""

    def __init__(self):
        link_components = [
            r"git\.kernel\.org",
            r"[0-9a-f]{40}$",
            r"/(commit|patch)/",
        ]
        patch_components = [r"/patch/"]
        super(GitKernel, self).__init__(
            link_components=link_components, patch_components=patch_components
        )


class Bitbucket(Provider):
    """Subclass for Bitbucket as a Provider."""

    def __init__(self):
        link_components = [r"bitbucket\.org", "/commits/"]
        patch_components = [r"/raw$"]
        patch_format_dict = {r"$": r"/raw"}
        super(Bitbucket, self).__init__(
            link_components=link_components,
            patch_components=patch_components,
            patch_format_dict=patch_format_dict,
        )


class Resource:
    """Base class for a resource w/r/t a URL.

    Attributes:
        url (str): The URL of the resource
        _links_xpaths (list[str]): A list of xpaths to use for scraping links/patches
        _normal_xpaths (list[str]): A list of xpaths to use for generic scraping
    """

    def __init__(self, url, **kwargs):
        self.url = url
        self._links_xpaths = kwargs.get("links_xpaths")
        self._normal_xpaths = kwargs.get("normal_xpaths")

    @staticmethod
    def get_resource(url):
        """Given a URL, return an Resource instance.

        Args:
            url (str): The URL to return the instance of.

        Returns:
            Resource: A resource instance.
        """

        resource = Resource(url, links_xpaths=["//body//a"])

        if re.match(r"^https://github\.com/", url):
            resource = Resource(
                url,
                links_xpaths=["//div[contains(@class, 'commit-message')]//a"],
            )

        elif re.match(r"^https://cve\.mitre\.org/", url):
            resource = Resource(
                url,
                links_xpaths=['//*[@id="GeneratedTable"]/table/tr[7]/td//a'],
            )

        elif re.match(r"^https://nvd\.nist\.gov/", url):
            resource = Resource(
                url,
                links_xpaths=[
                    '//table[@data-testid="vuln-hyperlinks-table"]/tbody//a'
                ],
            )

        elif re.match(
            r"^https://security\-tracker\.debian\.org/tracker/CVE\-\d+\-\d+$",
            url,
        ):
            resource = Resource(
                url,
                links_xpaths=["//pre/a"],
                normal_xpaths=[
                    "//table[3]//tr//td[1]//text()|//table[3]//tr//td[4]//text()"
                ],
            )

        elif re.match(
            r"^https://security\-tracker\.debian\.org/tracker/DSA\-\d+\-\d+$",
            url,
        ):
            resource = Resource(
                url,
                normal_xpaths=[
                    "//table//td//b[text()='References']/following::td[1]//a/text()"
                ],
            )

        elif re.match(r"^https://www.openwall\.com/lists/oss\-security", url):
            resource = Resource(url, links_xpaths=["//pre/a"])

        elif re.match(
            r"^https://lists\.fedoraproject\.org/archives/list/", url
        ):
            resource = Resource(
                url, link_xpaths=["//div[contains(@class, 'email-body')]//a"]
            )

        elif re.match(r"^https://lists\.debian\.org/", url):
            resource = Resource(url, link_xpaths=["//pre/a"])

        elif re.match(
            r"^https://bugzilla\.redhat\.com/show_bug\.cgi\?id=", url
        ):
            resource = Resource(
                url,
                links_xpaths=[
                    "//pre[contains(@class, 'bz_comment_text')]//a",
                    "//table[@id='external_bugs_table']//a",
                ],
            )

        elif re.match(r"^https://seclists\.org/", url):
            resource = Resource(url, links_xpaths=["//pre/a"])

        elif re.match(
            r"^https://access\.redhat\.com/labs/securitydataapi/"
            r"cve.json\?advisory=",
            url,
        ):
            resource = Resource(url, normal_xpaths=["//cve/text()"])

        elif re.match(
            r"^https://gitweb\.gentoo\.org/data/glsa\.git/plain/"
            r"glsa\-\d+\-\d+\.xml$",
            url,
        ):
            resource = Resource(url, normal_xpaths=["//references//uri/text()"])

        return resource

    @property
    def links_xpaths(self):
        """list[str]: Returns links xpaths, if instance has links xpaths."""
        links_xpaths = []
        if self._links_xpaths:
            links_xpaths = self._links_xpaths
        return links_xpaths

    @property
    def normal_xpaths(self):
        """list[str]: Returns normal xpaths, if instance has normal xpaths."""
        normal_xpaths = []
        if self._normal_xpaths:
            normal_xpaths = self._normal_xpaths
        return normal_xpaths


# TODO: Add this to a class.
def is_patch(link):
    """Determine if given link is a patch link.

    Args:
        link (str): The link to determine as patch or not.

    Returns:
        (str or None): If the link is a patch link then the formatted patch link,
            else None.
    """
    patch_link = None
    for provider_class in _PROVIDERS:
        provider = globals().get(provider_class)
        if not provider:
            logger.info(
                "Could not find provider %s in %s, ignoring.",
                provider_class,
                __name__,
            )
            continue
        patch_link = provider.belongs(link)
        if patch_link:
            break
    return patch_link
