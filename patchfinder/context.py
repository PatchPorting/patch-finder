import re


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

    def _rectify_vuln(self, vuln_id):
        return vuln_id.replace(" ", "-")


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
        parse_mode: The content type returned by base_url's response
    """

    def __init__(
        self,
        vuln_id,
        packages,
        base_url,
        entrypoint_urls=None,
        parse_mode=None,
        **kwargs
    ):
        self.base_url = base_url
        self.equivalent_vulns = []
        self.parse_mode = parse_mode
        self.allowed_keys = {
            "start_block",
            "end_block",
            "search_params",
            "as_per_block",
        }
        if not entrypoint_urls:
            entrypoint_urls = []
        self.__dict__.update(
            (k, v) for k, v in kwargs.items() if k in self.allowed_keys
        )
        super(UnparsableVulnerability, self).__init__(
            vuln_id, entrypoint_urls, packages
        )

    def clean_data(self, data):
        # Clean data scraped as needed
        pass


class CVE(Vulnerability):
    """Subclass for CVE"""

    def __init__(self, vuln_id, packages=None):
        vuln_id = self._rectify_vuln(vuln_id)
        entrypoint_urls = [
            "https://nvd.nist.gov/vuln/detail/{vuln_id}".format(
                vuln_id=vuln_id
            ),
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln_id}".format(
                vuln_id=vuln_id
            ),
            "https://security-tracker.debian.org/tracker/{vuln_id}".format(
                vuln_id=vuln_id
            ),
        ]
        super(CVE, self).__init__(vuln_id, entrypoint_urls, packages)


class DSA(UnparsableVulnerability):
    """Subclass for Debian Security Advisory (DSA)"""

    def __init__(self, vuln_id, packages=None):
        vuln_id = self._rectify_vuln(vuln_id)
        base_url = "https://security-tracker.debian.org/tracker/{vuln_id}".format(
            vuln_id=vuln_id
        )
        super(DSA, self).__init__(vuln_id, packages, base_url)


class RHSA(UnparsableVulnerability):
    """Subclass for Redhat Security Advisory (RHSA)"""

    def __init__(self, vuln_id, packages=None):
        vuln_id = self._rectify_vuln(vuln_id)
        base_url = (
            "https://access.redhat.com/labs/securitydataapi/"
            "cve.json?advisory={vuln_id}".format(vuln_id=vuln_id)
        )
        super(RHSA, self).__init__(vuln_id, packages, base_url)


class GLSA(UnparsableVulnerability):
    """Subclass for Gentoo Linux Security Advisory (GLSA)"""

    def __init__(self, vuln_id, packages=None):
        vuln_id = self._rectify_vuln(vuln_id)
        base_url = (
            "https://gitweb.gentoo.org/data/glsa.git/plain/"
            "{vuln_id}.xml".format(vuln_id=vuln_id.lower())
        )
        super(GLSA, self).__init__(vuln_id, packages, base_url)


def create_vuln(vuln_id, packages=None):
    vuln = None
    if re.match(r"^CVE\-\d+\-\d+$", vuln_id, re.I):
        vuln = CVE(vuln_id, packages)
    elif re.match(r"^DSA\-\d{3,}\-\d+$", vuln_id, re.I):
        vuln = DSA(vuln_id, packages)
    elif re.match(r"^RHSA\-\d+:\d+$", vuln_id, re.I):
        vuln = RHSA(vuln_id, packages)
    elif re.match(r"^GLSA( |\-)\d+-\d+$", vuln_id, re.I):
        vuln = GLSA(vuln_id, packages)
    return vuln
