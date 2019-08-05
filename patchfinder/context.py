"""Provides vulnerability identification and input functionality.

This module is used to set the context of patch finding by the spider.
"""
import re


class Vulnerability:
    """Base class for vulnerabilities.

    Attributes:
        vuln_id (str): The vulnerability ID.
        entrypoint_urls (list[str]): A list of entrypoint URLs for the vulnerability
        packages (dict{str: str} or None): Dictionary of packages the vuln affects.
            The keys are the provider to which the package name is relevant.
            Defaults to None.
        pattern (re.Pattern or None): A Regular expression of the vulnerability's
            notation. This pattern is matched to the input vulnerability to
            determine if the input vulnerability belongs to this vulnerability
            type. Defaults to None.
    """

    pattern = None

    def __init__(self, vuln_id, entrypoint_urls, packages=None):
        self.vuln_id = vuln_id
        self.entrypoint_urls = entrypoint_urls
        self.packages = packages

    @staticmethod
    def _normalize_vuln(vuln_id):
        return vuln_id.upper().replace(" ", "-").replace("_", "-")

    @classmethod
    def belongs(cls, vuln_id):
        if cls.pattern and cls.pattern.match(vuln_id):
            return True
        return False


class GenericVulnerability(Vulnerability):
    """Subclass for a generic vulnerability. Inherits from the Vulnerability
    class.

    While patches can be found with respect to this vulnerability, it would
    not be as expansive as finding them with respect to a CVE. Aliases of
    Generic vulnerabilities are thus determined by the spider to find patches.
    These aliases are scraped from the Generic Vulnerability's base URL.

    Attributes:
        base_url (str): The URL to start parsing from. For generic vulnerabilities
            this will point to a JSON-based, XML-based or HTML-based URL to
            facilitate "translation" of the vulnerability to CVEs or equivalent
            vulnerabilities.
        parse_mode (str): The content type returned by base_url's response.
    """

    def __init__(
            self,
            vuln_id,
            base_url,
            packages=None,
            entrypoint_urls=None,
            parse_mode=None,
    ):
        self.base_url = base_url
        self.equivalent_vulns = []
        self.parse_mode = parse_mode
        if not entrypoint_urls:
            entrypoint_urls = []
        super(GenericVulnerability, self).__init__(
            vuln_id, entrypoint_urls, packages=packages
        )


class CVE(Vulnerability):
    """Subclass for CVE (Common Vulnerabilities and Exposures). Inherits from
    the Vulnerability class.
    """

    pattern = re.compile(r"^CVE[ \-_]\d+[ \-_]\d+$", re.I)

    def __init__(self, vuln_id, packages=None):
        vuln_id = self._normalize_vuln(vuln_id)
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
        super(CVE, self).__init__(vuln_id, entrypoint_urls, packages=packages)


class DSA(GenericVulnerability):
    """Subclass for Debian Security Advisory (DSA). Inherits from
    the GenericVulnerability class.
    """

    pattern = re.compile(r"^DSA[ \-_]\d+([ \-_]\d+)?$", re.I)

    def __init__(self, vuln_id, packages=None):
        vuln_id = self._normalize_vuln(vuln_id)
        base_url = "https://security-tracker.debian.org/tracker/{vuln_id}".format(
            vuln_id=vuln_id
        )
        super(DSA, self).__init__(vuln_id, base_url, packages=packages)


class RHSA(GenericVulnerability):
    """Subclass for Redhat Security Advisory (RHSA). Inherits from
    the GenericVulnerability class.
    """

    pattern = re.compile(r"^RHSA[ \-_]\d+:\d+$", re.I)

    def __init__(self, vuln_id, packages=None):
        vuln_id = self._normalize_vuln(vuln_id)
        base_url = (
            "https://access.redhat.com/labs/securitydataapi/"
            "cve.json?advisory={vuln_id}".format(vuln_id=vuln_id)
        )
        super(RHSA, self).__init__(vuln_id, base_url, packages=packages)


class GLSA(GenericVulnerability):
    """Subclass for Gentoo Linux Security Advisory (GLSA). Inherits from
    the GenericVulnerability class.
    """

    pattern = re.compile(r"^GLSA[ \-_]\d+[ \-_]\d+$", re.I)

    def __init__(self, vuln_id, packages=None):
        vuln_id = self._normalize_vuln(vuln_id)
        base_url = (
            "https://gitweb.gentoo.org/data/glsa.git/plain/"
            "{vuln_id}.xml".format(vuln_id=vuln_id.lower())
        )
        super(GLSA, self).__init__(vuln_id, base_url, packages=packages)


def create_vuln(vuln_id, packages=None):
    """Returns a Vulnerability instance.

    Args:
        vuln_id (str): The vulnerability ID. It should be recognizable, i.e., there
            should be a corresponding subclass for the vulnerability with its
            regular expression based pattern.
        packages (dict{str: str} or None): A list of packages associated with the
            vulnerability. Defaults to None.

    Returns:
        Vulnerability: An appropriate Vulnerability instance.
    """
    vuln = None
    vuln_classes = [CVE, DSA, RHSA, GLSA]
    for vuln_class in vuln_classes:
        if vuln_class.belongs(vuln_id):
            vuln = vuln_class(vuln_id, packages)
            break
    return vuln


def create_vulns(*vulns):
    """Returns a list of Vulnerability instances.

    Args:
        *vulns (str or tuple[str, list[str]]): Can be just vulnerability IDs or
            tuples of vuln IDs and list of packages.

    Returns:
        list[Vulnerability]: A list of Vulnerability instances.
    """
    vuln_objects = []
    for vuln in vulns:
        if isinstance(vuln, tuple):
            vuln = create_vuln(vuln[0], packages=vuln[1])
        else:
            vuln = create_vuln(vuln)
        if vuln:
            vuln_objects.append(vuln)
    return vuln_objects
