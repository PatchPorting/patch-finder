import os
import re
import scrapy
import urllib.request

class DebianParser(object):
    """Class for parsing utilities relevant to Debian

    Attributes:
        cve_list_url: The link to the CVE list used in the Deb Sec Tracker
        cve_file: The path to the file used to save the cve list locally
    """

    cve_list_url = 'https://salsa.debian.org/security-tracker-team/security' \
                '-tracker/raw/master/data/CVE/list'
    cve_file = './cache/list'

    def _download_cve_list(self):
        if os.path.isfile(self.cve_file):
            return
        urllib.request.urlretrieve(self.cve_list_url, self.cve_file)

    def fixed_packages(self):
        self._download_cve_list()
        vuln_found = 0
        fixed_packages = []
        look_for_cve = re.compile(r'^{vuln_id}'.format(vuln_id=self.vuln_id))
        pkg_ver = re.compile(r'^\t\- (.+?) ([a-zA-Z\d\.\+\-\~:]+?$|[a-zA-Z\d\.' \
                             '\+\-\~:]+? )')
        f = open(self.cve_file)
        for line in f:
            if vuln_found:
                if re.match(r'^CVE', line):
                    break
                matches = pkg_ver.search(line)
                if matches and len(matches.groups()) is 2:
                    fixed_packages.append({'package': matches.group(1).strip(),
                                           'version': matches.group(2).strip()})
            elif look_for_cve.match(line):
                vuln_found = 1
        f.close()
        return fixed_packages

    def parse(self, vuln_id):
        self.vuln_id = vuln_id
        packages = self.fixed_packages()
        return []
