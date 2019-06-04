#TODO: figure out a more sophisticated way to construct URLs,
#      maybe define a method to substitute a %s for multiple strings
#NOTE: Might require an additional Patch Provider class

class Entrypoint(object):
    """Base class for an Entrypoint

    Attributes:
        urls: The entry urls to crawl
    """

    def __init__(self, urls):
        self.urls = urls


class Github(Entrypoint):
    """Subclass for GitHub as an entrypoint"""

    def __init__(self, vuln_id):
        urls = ['https://github.com/search?q='+vuln_id+'&type=Commits']
        super(Github, self).__init__(urls)


class NVD(Entrypoint):
    """Subclass for nvd.nist.org as an entrpoint"""

    def __init__(self, vuln_id):
        urls = ['https://nvd.nist.org/vuln/details/'+vuln_id]
        super(NVD, self).__init__(urls)


class MITRE(Entrypoint):
    """Subclass for cve.mitre.org as an entrypoint"""

    def __init__(self, vuln_id):
        urls = ['https://cve.mitre.org/cgi-bin/cvename.cgi?name='+vuln_id]
        super(MITRE, self).__init__(urls)

