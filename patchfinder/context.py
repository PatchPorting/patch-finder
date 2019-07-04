import os
import re
import patchfinder.entrypoint as entrypoint
import patchfinder.utils as utils
import patchfinder.settings as settings


class Context(object):
    """Base class for the run-time context of the patch-finder"""

    runnable_vulns = []

    def __init__(self, vuln):
        self.input_vuln = vuln

    def translate_vuln(self):
        self.input_vuln.translate()
        self.runnable_vulns = self.input_vuln.equivalent_cves


class Patch(object):
    """Base class for Patch

    Attributes:
        patch_link: Self explanatory
        source_version: The source version the patch pertains to
        reaching_path: The path taken by the finder to find the patch
    """

    def __init__(self, reaching_path, patch_link, source_version=None):
        self.patch_link = patch_link
        self.source_version = source_version
        self.reaching_path = reaching_path


class Vulnerability(object):
    """Base class for vulnerabilities

    Attributes:
        vuln_id: Self explanatory
        patches: List of patches relevant to the vuln
        packages: Dictionary of packages the vuln affects
                The keys are the provider to which the package name is relevant
    """

    def __init__(self, vuln_id, packages=None):
        self.vuln_id = vuln_id
        self.patches = []
        self.packages = packages

    def add_patch(self, context, patch_link, source_version=None):
        patch = Patch(context, patch_link, source_version)
        self.patches.append(patch)


class CVE(Vulnerability):
    """Subclass for CVE"""

    def __init__(self, vuln_id, packages=None):
        super(CVE, self).__init__(vuln_id, packages)
        self.entrypoint_URLs = [
            'https://nvd.nist.gov/vuln/detail/{vuln_id}' \
            .format(vuln_id=vuln_id),
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln_id}' \
            .format(vuln_id=vuln_id),
            'https://security-tracker.debian.org/tracker/{vuln_id}' \
            .format(vuln_id=vuln_id)
        ]


class DSA(Vulnerability):
    """Subclass for Debian Security Advisory (DSA)"""

    dsa_list_url = 'https://salsa.debian.org/security-tracker-team/security' \
            '-tracker/raw/master/data/DSA/list'
    dsa_file = os.path.join(settings.DOWNLOAD_DIRECTORY, 'dsa_list')
    cve_line = re.compile(r'^\s+\{(.+)\}')
    end_block = re.compile(r'^\s+\[')

    def __init__(self, vuln_id, packages=None):
        super(DSA, self).__init__(vuln_id, packages)
        self.start_block = re.compile(r'^\[.+\] {vuln_id}' \
                                      .format(vuln_id=vuln_id))
        self.entrypoint_URLs = []
        self.equivalent_cves = []

    def translate(self):
        utils.download_item(self.dsa_list_url, self.dsa_file)
        cves = list(utils.parse_raw_file(self.dsa_file,
                                         self.start_block,
                                         self.end_block,
                                         self.cve_line))
        if cves:
            cves = cves[0].group(1).split()
            self.equivalent_cves = cves


def create_vuln(vuln_id, packages=None):
    if re.match(r'^CVE\-\d+\-\d+$', vuln_id, re.I):
        return CVE(vuln_id, packages)
    return None
