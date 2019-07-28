# TODO: figure out a more sophisticated way to construct URLs,
#      maybe define a method to substitute a %s for multiple strings
import re
import patchfinder.utils as utils


class Provider(object):
    """Subclass for a patch Provider

    Inherits from Entrypoint
    Provider is an entity that provides patches.
    A provider can also be an Entrypoint.

    Attributes:
        link_components: A list of components in a patch link for this provider
        patch_components: A list of components in a patch-formatted link for
            this provider
        patch_format_dict: A dictionary for formatting a link into a patch link
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
        """Format link into patch link"""
        for i in self.patch_format_dict:
            link = re.sub(i, self.patch_format_dict[i], link)
        return link

    def is_patch_link(self, link):
        """Check if 'link' is a patch-formatted link"""
        return utils.match_all(link, self.patch_components)

    def match_link(self, link):
        """Checks if 'link' belongs to this provider"""
        return utils.match_all(link, self.link_components)

    def belongs(self, link):
        if self.match_link(link):
            if self.is_patch_link(link):
                return link
            else:
                return self.patch_format(link)
        return None


class Github(Provider):
    """Subclass for GitHub as a Provider"""

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
    """Subclass for Pagure as a Provider"""

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
    """Subclass for Gitlab as a Provider"""

    def __init__(self):
        link_components = [r"gitlab\.com", r"/commit/"]
        patch_components = {r"\.patch$"}
        super(Gitlab, self).__init__(
            link_components=link_components, patch_components=patch_components
        )


class GitKernel(Provider):
    """Subclass for git.kernel.org as a Provider"""

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


class Resource(object):
    """Base class for a resource w/r/t a URL

    Attributes:
        url: The URL of the resource
        links_xpaths: A list of xpaths to use for scraping links/patches
        normal_xpaths: A list of xpaths to use for generic scraping
    """

    def __init__(self, url, **kwargs):
        self.url = url
        self.links_xpaths = kwargs.get("links_xpaths")
        self.normal_xpaths = kwargs.get("normal_xpaths")

    def get_links_xpaths(self):
        links_xpaths = []
        if self.links_xpaths:
            links_xpaths = self.links_xpaths
        return links_xpaths

    def get_normal_xpaths(self):
        normal_xpaths = []
        if self.normal_xpaths:
            normal_xpaths = self.normal_xpaths
        return normal_xpaths


# TODO: Make this more sophisticated, maybe use something like getattr
def map_entrypoint_name(entrypoint_name):
    """given an entrypoint name return its corresponding Entrypoint object"""
    if entrypoint_name == "github.com":
        return Github()
    elif entrypoint_name == "pagure.io":
        return Pagure()
    elif entrypoint_name == "gitlab.com":
        return Gitlab()
    elif entrypoint_name == "git.kernel.org":
        return GitKernel()
    return None


def get_resource(url):
    """Given a URL, return an Resource instance.

    Args:
        url: The URL to return the instance of.

    Returns:
        A resource instance.
    """

    resource = Resource(url, links_xpaths=["//body//a"])

    if re.match(r"^https://github\.com/", url):
        resource = Resource(
            url, links_xpaths=["//div[contains(@class, 'commit-message')]//a"]
        )

    elif re.match(r"^https://cve\.mitre\.org/", url):
        resource = Resource(
            url, links_xpaths=['//*[@id="GeneratedTable"]/table/tr[7]/td//a']
        )

    elif re.match(r"^https://nvd\.nist\.gov/", url):
        resource = Resource(
            url,
            links_xpaths=[
                '//table[@data-testid="vuln-hyperlinks-table"]/tbody//a'
            ],
        )

    elif re.match(
        r"^https://security\-tracker\.debian\.org/tracker/CVE\-\d+\-\d+$", url
    ):
        resource = Resource(
            url,
            links_xpaths=["//pre/a"],
            normal_xpaths=[
                "//table[3]//tr//td[1]//text()|//table[3]//tr//td[4]//text()"
            ],
        )

    elif re.match(
        r"^https://security\-tracker\.debian\.org/tracker/DSA\-\d+\-\d+$", url
    ):
        resource = Resource(
            url,
            normal_xpaths=[
                "//table//td//b[text()='References']/following::td[1]//a/text()"
            ],
        )

    elif re.match(r"^https://www.openwall\.com/lists/oss\-security", url):
        resource = Resource(url, links_xpaths=["//pre/a"])

    elif re.match(r"^https://lists\.fedoraproject\.org/archives/list/", url):
        resource = Resource(
            url, link_xpaths=["//div[contains(@class, 'email-body')]//a"]
        )

    elif re.match(r"^https://lists\.debian\.org/", url):
        resource = Resource(url, link_xpaths=["//pre/a"])

    elif re.match(r"^https://bugzilla\.redhat\.com/show_bug\.cgi\?id=", url):
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


def is_patch(link):
    provider_names = ["github.com", "pagure.io", "gitlab.com", "git.kernel.org"]
    for provider_name in provider_names:
        provider = map_entrypoint_name(provider_name)
        patch_link = provider.belongs(link)
        if patch_link:
            return patch_link
    return None
