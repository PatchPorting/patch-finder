#TODO: figure out a more sophisticated way to construct URLs,
#      maybe define a method to substitute a %s for multiple strings
import re

class Entrypoint(object):
    """Base class for an Entrypoint

    Entrypoint is an entity crawled by the patch-finder.
    It can be understood as a seed in the crawling process.

    Attributes:
        name: Name of the entrypoint
        url: The entry url to crawl
        xpath: The xpath of the entrypoint to extract links from
    """
    xpath = '//body//a/@href'

    def __init__(self, url, xpath=None, name=None):
        """init method"""
        self.url = url
        self.xpath = xpath if xpath else '//body//a/@href'
        if name:
            self.name = name


class Provider(Entrypoint):
    """Subclass for a patch Provider

    Inherits from Entrypoint
    Provider is an entity that provides patches.
    A provider can also be an Entrypoint.

    Attributes:
        link_components: A list of components in a patch link for this provider
    """

    def __init__(self, link_components, url=None, xpath=None, name=None):
        if url:
            super(Provider, self).__init__(url=url, xpath=xpath, name=name)
        else:
            self.name = name
        self.link_components = link_components

    def match_link(self, link):
        """Checks if 'link' belongs to this provider"""
        if all(re.search(x, link) for x in self.link_components):
            return True
        return False


class Github(Provider):
    """Subclass for GitHub as a Provider"""

    def __init__(self, vuln_id=None, url=None):
        name = 'github.com'
        if vuln_id:
            url = 'https://github.com/search?q={vuln_id}&type=Commits'.format(vuln_id=vuln_id)
        link_components = [r'github\.com', r'/commit/']
        super(Github, self).__init__(link_components=link_components,
                                     url=url,
                                     name=name)


class Pagure(Provider):
    """Subclass for Pagure as a Provider"""

    def __init__(self, vuln_id=None, url=None):
        name = 'pagure.io'
        link_components = [r'pagure\.io', r'/[0-9a-f]{9}$']
        super(Pagure, self).__init__(link_components=link_components,
                                     url=url,
                                     name=name)



class NVD(Entrypoint):
    """Subclass for nvd.nist.org as an entrypoint"""

    def __init__(self, vuln_id=None, url=None):
        name = 'nvd.nist.gov'
        xpath = '//table[@data-testid="vuln-hyperlinks-table"]/tbody//a/@href'
        if vuln_id:
            url = 'https://nvd.nist.gov/vuln/detail/'+vuln_id
        super(NVD, self).__init__(url=url, xpath=xpath, name=name)


class MITRE(Entrypoint):
    """Subclass for cve.mitre.org as an entrypoint"""

    def __init__(self, vuln_id=None, url=None):
        name = 'cve.mitre.org'
        xpath = '//*[@id="GeneratedTable"]/table/tr[7]/td//a/@href'
        if vuln_id:
            url = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln_id}'.format(vuln_id=vuln_id)
        super(MITRE, self).__init__(url=url, xpath=xpath, name=name)


#TODO: Make this more sophisticated, maybe use something like getattr
def map_entrypoint_name(entrypoint_name, vuln_id=None):
    """given an entrypoint name return its corresponding Entrypoint object"""
    if entrypoint_name == 'github.com':
        return Github(vuln_id=vuln_id)
    elif entrypoint_name == 'cve.mitre.org':
        return MITRE(vuln_id=vuln_id)
    elif entrypoint_name == 'nvd.nist.gov':
        return NVD(vuln_id=vuln_id)
    return None


def get_entrypoint_from_url(url):
    if re.match(r'^https://github\.com/', url):
        return Github(url=url)
    elif re.match(r'^https://cve\.mitre\.org/cgi\-bin/cvename\.cgi\?name=CVE\-\d' \
                   '+\-\d+', url):
        return MITRE(url=url)
    elif re.match(r'^https://nvd\.nist\.gov/vuln/detail/CVE\-\d+\-\d+$', url):
        return NVD(url=url)
    return Entrypoint(url=url)


def is_patch(link):
    provider_names = ['github.com']
    for provider_name in provider_names:
        provider = map_entrypoint_name(provider_name)
        if provider.match_link(link):
            return True
    return False
