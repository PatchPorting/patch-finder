import os
import re
import patchfinder.utils as utils
import patchfinder.settings as settings


class Context(object):
    """Base class for the run-time context of the patch-finder

    Attributes:
        input_vuln: Self explanatory
        runnable_vulns: A list of vulnerabilities equivalent to the
            input vuln that can be used in the crawling process
    """

    def __init__(self, vuln):
        self.input_vuln = vuln
        self.runnable_vulns = []

    def translate_vuln(self):
        pass

    def run_crawlers(self):
        # init crawler process for each runnable vuln
        # and run crawler processes
        pass


class Vulnerability(object):
    """Base class for vulnerabilities

    Attributes:
        vuln_id: Self explanatory
        entrypoint_urls: A list of entrypoint URLs for the vulnerability
        packages: Dictionary of packages the vuln affects.
            The keys are the provider to which the package name is relevant
    """

    def __init__(self, vuln_id, entrypoint_urls, packages=None):
        self.vuln_id = vuln_id
        self.entrypoint_urls = entrypoint_urls
        self.packages = packages


class UnparsableVulnerability(Vulnerability):
    """Subclass for an unparsable vulnerability

    This vulnerability cannot be used by the default spider.

    Attributes:
        base_url: The URL to start parsing from. For unparsable vulnerabilities
            this will point to a JSON-based, XML-based or HTML-based URL to
            facilitate "translation" of the vulnerability to a parsable
            vulnerability
        equivalent_vulns: A list of equivalent vulnerabilities that can be
            used by the default spider.
        allowed_keys: A set of allowed keys for initialization
    """

    def __init__(self, vuln_id, packages, base_url, **kwargs):
        entrypoint_urls = []
        self.base_url = base_url
        self.equivalent_vulns = []
        self.allowed_keys = {'file_name', 'start_block', 'end_block',
                             'search_params', 'xpaths', 'key_list'}
        self.__dict__.update((k, v) for k, v in kwargs.items() \
                             if k in self.allowed_keys)
        super(UnparsableVulnerability, self).__init__(vuln_id,
                                                      entrypoint_urls,
                                                      packages)


class CVE(Vulnerability):
    """Subclass for CVE"""

    def __init__(self, vuln_id, packages=None):
        entrypoint_urls = [
            'https://nvd.nist.gov/vuln/detail/{vuln_id}' \
            .format(vuln_id=vuln_id),
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln_id}' \
            .format(vuln_id=vuln_id),
            'https://security-tracker.debian.org/tracker/{vuln_id}' \
            .format(vuln_id=vuln_id)
        ]
        super(CVE, self).__init__(vuln_id, entrypoint_urls, packages)


class DSA(UnparsableVulnerability):
    """Subclass for Debian Security Advisory (DSA)"""

    def __init__(self, vuln_id, packages=None):
        base_url = 'https://salsa.debian.org/security-tracker-team/' \
                'security-tracker/raw/master/data/DSA/list'
        file_name = os.path.join(settings.DOWNLOAD_DIRECTORY, 'dsa_list')
        start_block = re.compile(r'^\[.+\] {vuln_id}' \
                                      .format(vuln_id=vuln_id))
        end_block = re.compile(r'^\s+\[')
        search_params = re.compile(r'^\s+\{(.+)\}')
        super(DSA, self).__init__(vuln_id, packages, base_url,
                                  file_name=file_name,
                                  start_block=start_block,
                                  end_block=end_block,
                                  search_params=search_params)


class RHSA(UnparsableVulnerability):
    """Subclass for Redhat Security Advisory (RHSA)"""

    def __init__(self, vuln_id, packages=None):
        base_url = 'https://access.redhat.com/labs/securitydataapi/' \
            'cve.json?advisory={vuln_id}'.format(vuln_id=vuln_id)
        key_list = ['CVE']
        super(RHSA, self).__init__(vuln_id,
                                   packages,
                                   base_url,
                                   key_list=key_list)


def create_vuln(vuln_id, packages=None):
    if re.match(r'^CVE\-\d+\-\d+$', vuln_id, re.I):
        return CVE(vuln_id, packages)
    elif re.match(r'^DSA\-\d{3,}\-\d+$', vuln_id, re.I):
        return DSA(vuln_id, packages)
    elif re.match(r'^RHSA:\d+\-\d+$', vuln_id, re.I):
        return RHSA(vuln_id, packages)
    return None
