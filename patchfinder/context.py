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
        self.input_vuln.translate()
        self.runnable_vulns = self.input_vuln.equivalent_cves

    def run_crawlers(self):
        # init crawler process for each runnable vuln
        # and run crawler processes
        pass


class Vulnerability(object):
    """Base class for vulnerabilities

    Attributes:
        vuln_id: Self explanatory
        entrypoint_URLs: A list of entrypoint URLs for the vulnerability
        packages: Dictionary of packages the vuln affects.
            The keys are the provider to which the package name is relevant
    """

    def __init__(self, vuln_id, entrypoint_URLs, packages=None):
        self.vuln_id = vuln_id
        self.entrypoint_URLs = entrypoint_URLs
        self.packages = packages


class CVE(Vulnerability):
    """Subclass for CVE"""

    def __init__(self, vuln_id, packages=None):
        entrypoint_URLs = [
            'https://nvd.nist.gov/vuln/detail/{vuln_id}' \
            .format(vuln_id=vuln_id),
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln_id}' \
            .format(vuln_id=vuln_id),
            'https://security-tracker.debian.org/tracker/{vuln_id}' \
            .format(vuln_id=vuln_id)
        ]
        super(CVE, self).__init__(vuln_id, entrypoint_URLs, packages)


class DSA(Vulnerability):
    """Subclass for Debian Security Advisory (DSA)

    Attributes:
        dsa_list_url: URL of the DSA list
        dsa_file: Path to the locally stored DSA list
        cve_line: Regular expression denoting the CVEs corresponding to a DSA
        end_block: Regular expression denoting the end of a DSA block
        start_block: Regular expression denoting the DSA corresponding to the
            input vuln in the DSA list
        equivalent_cves: A list of CVEs equivalent to the input vuln
    """

    def __init__(self, vuln_id, packages=None):
        entrypoint_URLs = []
        self.dsa_list_url = 'https://salsa.debian.org/security-tracker-team/security' \
                '-tracker/raw/master/data/DSA/list'
        self.dsa_file = os.path.join(settings.DOWNLOAD_DIRECTORY, 'dsa_list')
        self.cve_line = re.compile(r'^\s+\{(.+)\}')
        self.end_block = re.compile(r'^\s+\[')
        self.start_block = re.compile(r'^\[.+\] {vuln_id}' \
                                      .format(vuln_id=vuln_id))
        self.equivalent_cves = []
        super(DSA, self).__init__(vuln_id, entrypoint_URLs, packages)

    def translate(self):
        utils.download_item(self.dsa_list_url, self.dsa_file)
        cves = list(utils.parse_raw_file(self.dsa_file,
                                         self.start_block,
                                         self.end_block,
                                         self.cve_line))
        if cves:
            self.equivalent_cves = cves[0].group(1).split()


def create_vuln(vuln_id, packages=None):
    if re.match(r'^CVE\-\d+\-\d+$', vuln_id, re.I):
        return CVE(vuln_id, packages)
    return None
