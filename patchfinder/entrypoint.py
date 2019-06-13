#TODO: figure out a more sophisticated way to construct URLs,
#      maybe define a method to substitute a %s for multiple strings
import re
import patchfinder.spiders.items as items
from urllib.parse import urlparse

class Provider(object):
    """Subclass for a patch Provider

    Inherits from Entrypoint
    Provider is an entity that provides patches.
    A provider can also be an Entrypoint.

    Attributes:
        link_components: A list of components in a patch link for this provider
    """

    def __init__(self, link_components, patch_components):
        self.link_components = link_components
        self.patch_components = patch_components

    def patch_format(self, link):
        for i in self.patch_components:
            link = re.sub(i, self.patch_components[i], link)
        return link

    def match_link(self, link):
        """Checks if 'link' belongs to this provider"""
        if all(re.search(x, link) for x in self.link_components):
            return True
        return False


class Github(Provider):
    """Subclass for GitHub as a Provider"""

    def __init__(self):
        link_components = [r'github\.com', r'/commit/', r'[0-9a-f]{40}$']
        patch_components = {r'$': r'.patch'}
        super(Github, self).__init__(link_components=link_components,
                                     patch_components=patch_components)


class Pagure(Provider):
    """Subclass for Pagure as a Provider"""

    def __init__(self, url=None):
        name = 'pagure.io'
        link_components = [r'pagure\.io', r'/[0-9a-f]{9}$']
        patch_components = {r'$': r'.patch'}
        super(Pagure, self).__init__(link_components=link_components,
                                     patch_components=patch_components)


#TODO: Make this more sophisticated, maybe use something like getattr
def map_entrypoint_name(entrypoint_name):
    """given an entrypoint name return its corresponding Entrypoint object"""
    if entrypoint_name == 'github.com':
        return Github()
    elif entrypoint_name == 'pagure.io':
        return Pagure()
    return None


def get_xpath(url):
    """Given a URL, map it to its Entrypoint object"""
    if re.match(r'^https://github\.com/.+?/.+?/issues/\d+$', url):
        return ['//div[contains(@class, \'commit-message\')]//a']

    elif re.match(r'^https://cve\.mitre\.org/cgi\-bin/cvename\.cgi\?name=CVE' \
                  '\-\d+\-\d+', url):
        return ['//*[@id="GeneratedTable"]/table/tr[7]/td//a']

    elif re.match(r'^https://nvd\.nist\.gov/vuln/detail/CVE\-\d+\-\d+$', url):
        return ['//table[@data-testid="vuln-hyperlinks-table"]/tbody//a']

    elif re.match(r'^https://security\-tracker\.debian\.org/tracker/CVE\-\d' \
                  '+\-\d+$', url):
        return ['//pre/a']

    elif re.match(r'^https://www.openwall\.com/lists/oss\-security', url):
        return ['//pre/a']

    elif re.match(r'^https://lists\.fedoraproject\.org/archives/list/', url):
        return ['//div[contains(@class, \'email-body\')]//a'] 

    elif re.match(r'^https://bugzilla\.redhat\.com/show_bug\.cgi\?id=', url):
        return ['//pre[contains(@class, \'bz_comment_text\')]//a', 
                '//table[@id=\'external_bugs_table\']//a']

    return ['//body//a']


def is_patch(link):
    provider_names = ['github.com', 'pagure.io']
    for provider_name in provider_names:
        provider = map_entrypoint_name(provider_name)
        if provider.match_link(link):
            return provider.patch_format(link)
    return None
