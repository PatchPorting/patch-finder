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
            super(Provider, self).__init__(urls=urls)
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
        self.name = 'github'
        super(Github, self).__init__(link_components, urls)


class NVD(Entrypoint):
    """Subclass for nvd.nist.org as an entrypoint"""

    def __init__(self, vuln_id):
        self.name = 'nvd.nist.gov'
        urls = ['https://nvd.nist.gov/vuln/details/'+vuln_id]
        super(NVD, self).__init__(urls=urls)


class MITRE(Entrypoint):
    """Subclass for cve.mitre.org as an entrypoint"""

    def __init__(self, vuln_id):
        self.name = 'cve.mitre.org'
        urls = ['https://cve.mitre.org/cgi-bin/cvename.cgi?name='+vuln_id]
        super(MITRE, self).__init__(urls=urls)


def create_entrypoint(entrypoint_name, vuln_id=None):
    if entrypoint_name == 'github':
        return Github(vuln_id)
    elif entrypoint_name == 'cve.mitre.org':
        return MITRE(vuln_id)
    elif entrypoint_name == 'nvd.nist.gov':
        return NVD(vuln_id)
    return None


def is_patch(link):
    provider_names = ['github']
    for provider_name in provider_names:
        provider = create_entrypoint(provider_name)
        if provider.match_link(link):
            return True
    return False
