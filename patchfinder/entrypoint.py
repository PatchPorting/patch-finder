#TODO: figure out a more sophisticated way to construct URLs,
#      maybe define a method to substitute a %s for multiple strings

class Entrypoint(object):
    """Base class for an Entrypoint

    Entrypoint is an entity crawled by the patch-finder.
    It can be understood as a seed in the crawling process.

    Attributes:
        urls: The entry urls to crawl
    """

    def __init__(self, urls):
        """init method"""
        self.urls = urls


class Provider(Entrypoint):
    """Subclass for a patch Provider

    Inherits from Entrypoint
    Provider is an entity that provides patches.
    A provider can also be an Entrypoint.

    Attributes:
        link_components: A list of components in a patch link for this provider
    """

    def __init__(self, link_components, urls):
        """init method, calls init of Entrypoint if urls is not None

        Args:
            link_components: A list of components in a patch link for this provider
            urls: A list of URLs the finder will crawl w/r/t this provider
        """
        if urls:
            super(Provider, self).__init__(urls)
        self.link_components = link_components

    def match_link(self, link):
        """Checks if 'link' belongs to this provider"""
        if all(x in link for x in self.link_components):
            return True
        return False


class Github(Provider):
    """Subclass for GitHub as a Provider"""

    def __init__(self, vuln_id=None):
        if vuln_id:
            urls = ['https://github.com/search?q='+vuln_id+'&type=Commits']
        else:
            urls = None
        link_components = ['github.com', '/commit/']
        super(Github, self).__init__(link_components, urls)


class NVD(Entrypoint):
    """Subclass for nvd.nist.org as an entrypoint"""

    def __init__(self, vuln_id):
        urls = ['https://nvd.nist.org/vuln/details/'+vuln_id]
        super(NVD, self).__init__(urls)


class MITRE(Entrypoint):
    """Subclass for cve.mitre.org as an entrypoint"""

    def __init__(self, vuln_id):
        urls = ['https://cve.mitre.org/cgi-bin/cvename.cgi?name='+vuln_id]
        super(MITRE, self).__init__(urls)

