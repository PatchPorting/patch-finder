import os
import re
import urllib.request
from bs4 import BeautifulSoup
DOWNLOAD_DIRECTORY = './cache/'

class DebianParser(object):
    """Class for parsing utilities relevant to Debian

    Attributes:
        cve_list_url: The link to the CVE list used in the Deb Sec Tracker
        cve_file: The path to the file used to save the cve list locally
        fixed_packages: A list of fixed Debian packages w/r/t the input
            vulnerability
    """

    cve_list_url = 'https://salsa.debian.org/security-tracker-team/security' \
                '-tracker/raw/master/data/CVE/list'
    cve_file = DOWNLOAD_DIRECTORY + 'list'
    fixed_packages = []

    #TODO: urlretrieve is most probably deprecated, find something else
    def _download_item(self, url, save_as):
        if os.path.isfile(save_as):
            return
        urllib.request.urlretrieve(url, save_as)

    def find_fixed_packages(self):
        self.fixed_packages = []
        self._download_item(self.cve_list_url, self.cve_file)
        vuln_found = 0
        look_for_cve = re.compile(r'^{vuln_id}'.format(vuln_id=self.vuln_id))
        pkg_ver = re.compile(r'^\t\- (.+?) ([a-zA-Z\d\.\+\-\~:]+?$|[a-zA-Z' \
                             '\d\.\+\-\~:]+? )')
        cve_file = open(self.cve_file)
        try:
            for line in cve_file:
                if vuln_found:
                    if re.match(r'^CVE', line):
                        break
                    matches = pkg_ver.search(line)
                    if matches and len(matches.groups()) is 2:
                        pkg = matches.group(1).strip()
                        ver = re.sub('^.+:', '', matches.group(2).strip())
                        self.fixed_packages.append({'package': pkg,
                                                    'version': ver})
                elif look_for_cve.match(line):
                    vuln_found = 1
        finally:
            cve_file.close()

    def retrieve_packages(self):
        for package in self.fixed_packages:
            snapshot_url = 'https://snapshot.debian.org/package/{pkg}/{ver}/' \
                    .format(pkg=package['package'], ver=package['version'])
            snapshot_html = urllib.request.urlopen(snapshot_url)
            soup = BeautifulSoup(snapshot_html, 'html.parser')
            find_pkg = re.compile(r'/({pkg}_{ver}\.(debian\.tar\..+|diff\..+' \
                                  '))$'.format(pkg=package['package'],
                                               ver=package['version']))
            pkg_url = soup.find('a', href=find_pkg)
            assert pkg_url, "Couldn't find package {pkg} {ver} on {url}" \
                    .format(pkg=package['package'],
                            ver=package['version'],
                            url=snapshot_url)
            pkg_url = 'https://snapshot.debian.org/' + pkg_url['href']
            pkg_name = find_pkg.search(pkg_url)
            self._download_item(pkg_url, DOWNLOAD_DIRECTORY + pkg_name.group(1))

    def parse(self, vuln_id):
        self.vuln_id = vuln_id
        self.find_fixed_packages()
        self.retrieve_packages()
        return []
